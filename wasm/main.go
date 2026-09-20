//go:build js && wasm

// WebAssembly entry point for Visual Sysmon Modular.
//
// This file is copied into <sysmon-modular>/tooling/cmd/vsmwasm/ at build time
// (the packages it uses are `internal`, so it must live inside upstream's module)
// and exposes upstream's merge / validate / analyze / coverage / diff logic as
// `globalThis.sysmonModular`. Every function takes one plain JS object and
// returns one; errors are reported as {ok:false, error:"..."}.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/olafhartong/sysmon-modular/tooling/internal/analyze"
	"github.com/olafhartong/sysmon-modular/tooling/internal/coverage"
	"github.com/olafhartong/sysmon-modular/tooling/internal/semantic"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
)

const wrapperVersion = "1.0"

// Same default as merger.defaultTemplate (unexported upstream).
const defaultTemplate = `<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <DnsLookup>False</DnsLookup>
  <ArchiveDirectory>Sysmon</ArchiveDirectory>
  <EventFiltering/>
</Sysmon>`

type module struct {
	Path string `json:"path"`
	XML  string `json:"xml"`
}

type finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Detail   string `json:"detail"`
}

func toFindings(in []validate.Finding) []finding {
	out := make([]finding, 0, len(in))
	for _, f := range in {
		out = append(out, finding{Code: f.Code, Severity: string(f.Severity), Path: f.Path, Line: f.Line, Message: f.Message, Detail: f.Detail})
	}
	return out
}

// ── JS plumbing ──────────────────────────────────────────────────────────────
func decodeArg(args []js.Value, v any) error {
	if len(args) == 0 || args[0].IsUndefined() || args[0].IsNull() {
		return nil
	}
	s := js.Global().Get("JSON").Call("stringify", args[0]).String()
	return json.Unmarshal([]byte(s), v)
}

func encode(v any) js.Value {
	b, err := json.Marshal(v)
	if err != nil {
		return encode(map[string]any{"ok": false, "error": err.Error()})
	}
	return js.Global().Get("JSON").Call("parse", string(b))
}

func fail(format string, a ...any) js.Value {
	return encode(map[string]any{"ok": false, "error": fmt.Sprintf(format, a...)})
}

func wrap(fn func([]js.Value) js.Value) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) (ret any) {
		defer func() {
			if r := recover(); r != nil {
				ret = fail("panic: %v", r)
			}
		}()
		return fn(args)
	})
}

// ── merge ────────────────────────────────────────────────────────────────────
type mergeRequest struct {
	Modules              []module `json:"modules"`
	Template             string   `json:"template"`
	SysmonVersion        string   `json:"sysmonVersion"`
	Unsupported          string   `json:"unsupported"`
	PreserveComments     bool     `json:"preserveComments"`
	ForceGroupRelationOr bool     `json:"forceGroupRelationOr"`
	Analyze              bool     `json:"analyze"`
	SchemaValidate       *bool    `json:"schemaValidate"`
}

func compareSchema(a, b string) int {
	parse := func(s string) []int {
		parts := strings.Split(s, ".")
		out := make([]int, len(parts))
		for i, p := range parts {
			out[i], _ = strconv.Atoi(p)
		}
		return out
	}
	aa, bb := parse(a), parse(b)
	for len(aa) < len(bb) {
		aa = append(aa, 0)
	}
	for len(bb) < len(aa) {
		bb = append(bb, 0)
	}
	for i := range aa {
		if aa[i] != bb[i] {
			if aa[i] < bb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func merge(args []js.Value) js.Value {
	var req mergeRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	if len(req.Modules) == 0 {
		return fail("no input modules")
	}
	if req.SysmonVersion == "" {
		req.SysmonVersion = "15"
	}
	if req.Unsupported == "" {
		req.Unsupported = "warn"
	}
	if req.Unsupported != "warn" && req.Unsupported != "exclude" {
		return fail("unsupported must be warn or exclude")
	}
	var findings []validate.Finding
	var warnings []string

	// 1. syntax check + collect RuleGroups (mirror of merger.Merge over in-memory docs)
	var groups []*sysmonxml.Node
	maxSchema := ""
	for _, m := range req.Modules {
		doc, err := sysmonxml.Parse([]byte(m.XML), req.PreserveComments)
		if err != nil {
			findings = append(findings, validate.SyntaxFinding(m.Path, err))
			continue
		}
		if doc.Root == nil || doc.Root.Name != "Sysmon" {
			findings = append(findings, validate.Finding{Code: "SYS002", Severity: validate.Error, Path: m.Path, Message: "root element must be Sysmon"})
			continue
		}
		if schema := doc.Root.AttrValue("schemaversion"); compareSchema(schema, maxSchema) > 0 {
			maxSchema = schema
		}
		found := false
		doc.Root.Walk(func(rg *sysmonxml.Node) {
			if rg.Name != "RuleGroup" {
				return
			}
			found = true
			clone := rg.Clone()
			if req.ForceGroupRelationOr {
				clone.SetAttr("groupRelation", "or")
			}
			groups = append(groups, clone)
		})
		if !found {
			warnings = append(warnings, m.Path+": no RuleGroup elements found")
		}
	}
	if validate.HasErrors(findings) {
		return encode(map[string]any{"ok": false, "error": "XML syntax validation failed", "findings": toFindings(findings), "warnings": warnings})
	}

	// 2. template
	tpl := req.Template
	if strings.TrimSpace(tpl) == "" {
		tpl = defaultTemplate
	}
	out, err := sysmonxml.Parse([]byte(tpl), req.PreserveComments)
	if err != nil {
		return fail("template: %v", err)
	}
	if maxSchema != "" {
		out.Root.SetAttr("schemaversion", maxSchema)
	}
	ef := out.Root.FirstChild("EventFiltering")
	if ef == nil {
		ef = sysmonxml.Element("EventFiltering", nil)
		out.Root.Children = append(out.Root.Children, ef)
	}
	ef.Children = nil
	ef.Children = append(ef.Children, groups...)

	// 3. target version + compatibility
	target, err := validate.ResolveBinarySchema(req.SysmonVersion)
	if err != nil {
		return fail("%v", err)
	}
	out.Root.SetAttr("schemaversion", target.SchemaVersion)
	var compat []validate.Finding
	if req.Unsupported == "exclude" {
		compat, err = validate.ExcludeBinaryUnsupported(out, "merged", req.SysmonVersion)
	} else {
		compat, err = validate.BinaryCompatibility(out, "merged", req.SysmonVersion)
	}
	if err != nil {
		return fail("%v", err)
	}
	findings = append(findings, compat...)

	// 4. schema validation (SYS201 superseded by SYS204 like upstream)
	if req.SchemaValidate == nil || *req.SchemaValidate {
		for _, f := range validate.Schema(out, "merged") {
			if f.Code == "SYS201" {
				continue
			}
			findings = append(findings, f)
		}
	}
	// 5. analyzer
	if req.Analyze {
		findings = append(findings, analyze.Config(out, "merged")...)
	}
	return encode(map[string]any{
		"ok":            !validate.HasErrors(findings),
		"xml":           out.String(),
		"schemaversion": target.SchemaVersion,
		"findings":      toFindings(findings),
		"warnings":      warnings,
		"moduleCount":   len(req.Modules),
		"groupCount":    len(groups),
	})
}

// ── validate ─────────────────────────────────────────────────────────────────
type validateRequest struct {
	Path             string `json:"path"`
	XML              string `json:"xml"`
	SysmonVersion    string `json:"sysmonVersion"`
	Unsupported      string `json:"unsupported"`
	PreserveComments bool   `json:"preserveComments"`
	Schema           *bool  `json:"schema"`
	Mitre            *bool  `json:"mitre"`
}

func validateFn(args []js.Value) js.Value {
	var req validateRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	if req.Path == "" {
		req.Path = "module.xml"
	}
	doc, err := sysmonxml.Parse([]byte(req.XML), req.PreserveComments)
	if err != nil {
		f := validate.SyntaxFinding(req.Path, err)
		return encode(map[string]any{"ok": false, "findings": toFindings([]validate.Finding{f})})
	}
	var findings []validate.Finding
	if req.Schema == nil || *req.Schema {
		findings = append(findings, validate.Schema(doc, req.Path)...)
	}
	if req.Mitre == nil || *req.Mitre {
		findings = append(findings, validate.MITRE(doc, req.Path)...)
	}
	if req.SysmonVersion != "" {
		var compat []validate.Finding
		if req.Unsupported == "exclude" {
			compat, err = validate.ExcludeBinaryUnsupported(doc, req.Path, req.SysmonVersion)
		} else {
			compat, err = validate.BinaryCompatibility(doc, req.Path, req.SysmonVersion)
		}
		if err != nil {
			return fail("%v", err)
		}
		findings = append(findings, compat...)
	}
	return encode(map[string]any{"ok": !validate.HasErrors(findings), "findings": toFindings(findings)})
}

// ── analyze (standalone, on any config) ──────────────────────────────────────
func analyzeFn(args []js.Value) js.Value {
	var req validateRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	doc, err := sysmonxml.Parse([]byte(req.XML), false)
	if err != nil {
		return fail("%v", err)
	}
	return encode(map[string]any{"ok": true, "findings": toFindings(analyze.Config(doc, req.Path))})
}

// ── coverage ─────────────────────────────────────────────────────────────────
type coverageRequest struct {
	Modules       []module `json:"modules"`
	Format        string   `json:"format"`
	AttackVersion string   `json:"attackVersion"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
}

func coverageFn(args []js.Value) js.Value {
	var req coverageRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	docs := map[string]*sysmonxml.Document{}
	var errs []string
	for _, m := range req.Modules {
		doc, err := sysmonxml.Parse([]byte(m.XML), false)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", m.Path, err))
			continue
		}
		docs[m.Path] = doc
	}
	report := coverage.Build(docs)
	switch req.Format {
	case "", "json":
		return encode(map[string]any{"ok": true, "report": report, "errors": errs})
	case "navigator":
		if req.AttackVersion == "" {
			req.AttackVersion = "18"
		}
		var notes []string
		for _, r := range coverage.NavigatorRemappings(report, req.AttackVersion) {
			notes = append(notes, fmt.Sprintf("ATT&CK 18 compatibility: remapped %s to %s", r.From, r.To))
		}
		var b bytes.Buffer
		if err := coverage.WriteNavigatorWithOptions(&b, report, coverage.NavigatorOptions{
			Name: req.Name, Description: req.Description, AttackVersion: req.AttackVersion,
		}); err != nil {
			return fail("render Navigator layer: %v", err)
		}
		return encode(map[string]any{"ok": true, "layer": b.String(), "notes": notes, "errors": errs})
	}
	return fail("unsupported coverage format %q", req.Format)
}

// ── diff ─────────────────────────────────────────────────────────────────────
type diffRequest struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

func diffFn(args []js.Value) js.Value {
	var req diffRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	b, err := sysmonxml.Parse([]byte(req.Before), false)
	if err != nil {
		return fail("before: %v", err)
	}
	a, err := sysmonxml.Parse([]byte(req.After), false)
	if err != nil {
		return fail("after: %v", err)
	}
	d := semantic.Compare(semantic.Extract(b), semantic.Extract(a))
	return encode(map[string]any{"ok": true, "diff": d})
}

// ── format ───────────────────────────────────────────────────────────────────
func formatFn(args []js.Value) js.Value {
	var req validateRequest
	if err := decodeArg(args, &req); err != nil {
		return fail("bad request: %v", err)
	}
	doc, err := sysmonxml.Parse([]byte(req.XML), true)
	if err != nil {
		return fail("%v", err)
	}
	return encode(map[string]any{"ok": true, "xml": doc.String()})
}

func versionFn(args []js.Value) js.Value {
	return encode(map[string]any{"ok": true, "wrapper": wrapperVersion, "tool": "sysmon-modular configuration tool (wasm)"})
}

func main() {
	api := js.Global().Get("Object").New()
	api.Set("merge", wrap(merge))
	api.Set("validate", wrap(validateFn))
	api.Set("analyze", wrap(analyzeFn))
	api.Set("coverage", wrap(coverageFn))
	api.Set("diff", wrap(diffFn))
	api.Set("format", wrap(formatFn))
	api.Set("version", wrap(versionFn))
	js.Global().Set("sysmonModular", api)
	if ready := js.Global().Get("__sysmonModularReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {} // keep the Go runtime alive
}

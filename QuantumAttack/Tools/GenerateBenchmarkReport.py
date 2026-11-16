#!/usr/bin/env python3
"""Generate a self-contained HTML dashboard and derived CSV from QuantumAttack benchmark output."""
from __future__ import annotations
import argparse, csv, html, math, os, statistics, sys
from collections import defaultdict
from pathlib import Path

COLORS = {"CPU-SINGLE":"#64748b", "CPU-MULTI":"#0f766e", "CUDA-GPU":"#2563eb", "CUDA-MULTI-GPU":"#9333ea", "CUDA-SINGLE":"#2563eb", "CUDA-MULTI":"#9333ea"}

def number(row, key, default=0.0):
    try:
        value = float(row.get(key, default) or default)
        return value if math.isfinite(value) else default
    except (TypeError, ValueError):
        return default

def load_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    required = {"algorithm", "backend", "status", "qubits", "mean_ms", "state_vector_bytes"}
    if not rows:
        raise ValueError("Input CSV contains no benchmark rows.")
    missing = required - set(rows[0])
    if missing:
        raise ValueError("CSV is missing required columns: " + ", ".join(sorted(missing)))
    return rows

def svg_chart(title, points, y_label, log_y=False, width=860, height=330):
    pad_l, pad_r, pad_t, pad_b = 72, 24, 42, 52
    pw, ph = width-pad_l-pad_r, height-pad_t-pad_b
    if not points:
        return f'<section class="chart"><h2>{html.escape(title)}</h2><p class="muted">No eligible data.</p></section>'
    xs = sorted({int(p["x"]) for p in points})
    x_min, x_max = min(xs), max(xs)
    if x_min == x_max: x_max = x_min + 1
    vals = [max(1e-12, float(p["y"])) for p in points if float(p["y"]) > 0]
    if not vals:
        return f'<section class="chart"><h2>{html.escape(title)}</h2><p class="muted">No positive measurements.</p></section>'
    if log_y:
        lo, hi = math.log10(min(vals)), math.log10(max(vals))
        if hi-lo < .15: hi = lo + .15
        trans = lambda v: math.log10(max(1e-12, v))
        inv = lambda v: 10**v
    else:
        lo, hi = 0.0, max(vals)*1.12
        if hi <= 0: hi = 1.0
        trans, inv = lambda v:v, lambda v:v
    def xp(x): return pad_l + (x-x_min)/(x_max-x_min)*pw
    def yp(y): return pad_t + ph - (trans(y)-lo)/(hi-lo)*ph
    parts=[f'<section class="chart"><h2>{html.escape(title)}</h2><svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">']
    for i in range(5):
        v=lo+(hi-lo)*i/4; y=pad_t+ph-i*ph/4
        label=f'{inv(v):.3g}'
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" stroke="#e2e8f0"/><text x="{pad_l-9}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{label}</text>')
    for x in xs:
        xx=xp(x); parts.append(f'<text x="{xx:.1f}" y="{height-24}" text-anchor="middle" font-size="11" fill="#64748b">{x}</text>')
    grouped=defaultdict(list)
    for p in points: grouped[p["series"]].append(p)
    for series, seq in grouped.items():
        seq.sort(key=lambda p:p["x"]); color=COLORS.get(series,"#475569")
        coords=" ".join(f'{xp(p["x"]):.1f},{yp(p["y"]):.1f}' for p in seq if p["y"]>0)
        if coords: parts.append(f'<polyline points="{coords}" fill="none" stroke="{color}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>')
        for p in seq:
            if p["y"]<=0: continue
            xx,yy=xp(p["x"]),yp(p["y"]); tip=html.escape(f'{series} · {p["x"]} qubits · {p["y"]:.5g}')
            parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="4" fill="{color}"><title>{tip}</title></circle>')
    parts.append(f'<text x="{pad_l+pw/2}" y="{height-3}" text-anchor="middle" font-size="12" fill="#334155">Qubits</text>')
    parts.append(f'<text x="16" y="{pad_t+ph/2}" transform="rotate(-90 16 {pad_t+ph/2})" text-anchor="middle" font-size="12" fill="#334155">{html.escape(y_label)}</text>')
    parts.append('</svg><div class="legend">')
    for series in grouped: parts.append(f'<span><i style="background:{COLORS.get(series,"#475569")}"></i>{html.escape(series)}</span>')
    parts.append('</div></section>')
    return ''.join(parts)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv", nargs="?", default="Output/algorithm_benchmark.csv")
    ap.add_argument("--html", default="Output/algorithm_benchmark_report.html")
    ap.add_argument("--summary-csv", default="Output/algorithm_benchmark_summary.csv")
    args=ap.parse_args(); rows=load_rows(args.csv)
    usable=[r for r in rows if r.get("status","").upper() in ("OK","PARTIAL") and number(r,"successful_runs")>0 and number(r,"mean_ms")>0]
    bykey={(r["algorithm"],r["backend"],int(number(r,"qubits"))):r for r in usable}
    algorithms=sorted({r["algorithm"] for r in rows})
    summary=[]
    for r in rows:
        alg,backend,q=r["algorithm"],r["backend"],int(number(r,"qubits"))
        cpu=bykey.get((alg,"CPU-SINGLE",q))
        speedup=number(cpu,"mean_ms")/number(r,"mean_ms") if cpu and number(r,"mean_ms")>0 else 0.0
        gpu_count=len([x for x in (r.get("gpu_devices","").split(";") if r.get("gpu_devices") else []) if x.strip()])
        efficiency=speedup/gpu_count if gpu_count>0 and backend in ("CUDA-MULTI", "CUDA-MULTI-GPU") else 0.0
        summary.append({"algorithm":alg,"backend":backend,"qubits":q,"status":r.get("status",""),"mean_ms":number(r,"mean_ms"),"median_ms":number(r,"median_ms"),"stddev_ms":number(r,"stddev_ms"),"state_vector_bytes":int(number(r,"state_vector_bytes")),"speedup_vs_cpu_single":speedup,"multi_gpu_efficiency":efficiency,"gpu_kernel_ms":number(r,"gpu_kernel_ms"),"gpu_transfer_ms":number(r,"gpu_transfer_ms"),"inter_gpu_transfer_ms":number(r,"inter_gpu_transfer_ms"),"experiment_pass_rate":number(r,"experiment_pass_rate")})
    Path(args.summary_csv).parent.mkdir(parents=True,exist_ok=True)
    fields=list(summary[0].keys())
    with open(args.summary_csv,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(summary)
    charts=[]
    for alg in algorithms:
        subset=[s for s in summary if s["algorithm"]==alg and s["status"].upper() in ("OK","PARTIAL")]
        for metric,title,label,log in [("mean_ms",f"{alg}: execution time","Mean time (ms)",True),("state_vector_bytes",f"{alg}: state-vector memory","State-vector bytes",True),("speedup_vs_cpu_single",f"{alg}: speedup vs CPU Single","Speedup (×)",False)]:
            pts=[{"x":s["qubits"],"y":s[metric],"series":s["backend"]} for s in subset if s[metric]>0]
            charts.append(svg_chart(title,pts,label,log))
        mg=[s for s in subset if s["backend"] in ("CUDA-MULTI", "CUDA-MULTI-GPU") and s["multi_gpu_efficiency"]>0]
        if mg: charts.append(svg_chart(f"{alg}: Multi-GPU efficiency",[{"x":s["qubits"],"y":s["multi_gpu_efficiency"],"series":"CUDA-MULTI"} for s in mg],"Efficiency (×)",False))
    ok=sum(1 for r in rows if r.get("status","").upper()=="OK")
    unavailable=sum(1 for r in rows if r.get("status","").upper() in ("UNAVAILABLE","SKIPPED"))
    failed=sum(1 for r in rows if r.get("status","").upper()=="FAILED")
    cards=f'<div class="cards"><div><b>{len(rows)}</b><span>rows</span></div><div><b>{ok}</b><span>OK</span></div><div><b>{unavailable}</b><span>Unavailable / skipped</span></div><div><b>{failed}</b><span>Failed</span></div></div>'
    table_rows=[]
    for s in summary:
        table_rows.append('<tr>'+''.join(f'<td>{html.escape(str(s[k]))}</td>' for k in ["algorithm","backend","qubits","status"])+f'<td>{s["mean_ms"]:.5g}</td><td>{s["speedup_vs_cpu_single"]:.4g}</td><td>{s["experiment_pass_rate"]:.1%}</td></tr>')
    table='<section class="chart"><h2>Benchmark data</h2><div class="tablewrap"><table><thead><tr><th>Algorithm</th><th>Backend</th><th>Qubits</th><th>Status</th><th>Mean ms</th><th>Speedup ×</th><th>Pass rate</th></tr></thead><tbody>'+''.join(table_rows)+'</tbody></table></div></section>'
    note='All timings are classical state-vector simulation measurements. They are not quantum-hardware timings. Speedup is computed only where a matching CPU-SINGLE row exists. Multi-GPU efficiency is an approximate speedup divided by the number of listed devices; it is not a substitute for a controlled scaling experiment.'
    doc='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>QuantumAttack Benchmark Report</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f1f5f9;color:#0f172a;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}.wrap{max-width:1100px;margin:auto;padding:28px 18px 50px}header{margin-bottom:20px}h1{font-size:28px;margin:0 0 5px}h2{font-size:17px;margin:0 0 12px}.muted,small{color:#64748b}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:18px 0}.cards div,.chart{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:16px}.cards b{display:block;font-size:25px}.cards span{color:#64748b}.chart{margin:14px 0;overflow:hidden}.chart svg{width:100%;height:auto;display:block}.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;color:#475569;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap}th{background:#f8fafc;color:#475569}.note{background:#e0f2fe;border-radius:10px;padding:13px;color:#075985;margin-top:18px}footer{margin-top:22px;color:#64748b;font-size:12px}</style></head><body><main class="wrap"><header><h1>QuantumAttack Benchmark Report</h1><div class="muted">Generated from '''+html.escape(os.path.basename(args.csv))+'''</div></header>'''+cards+''.join(charts)+table+f'<div class="note">{html.escape(note)}</div><footer>Generated by QuantumAttack 2.7 report tooling. Charts are embedded SVG; this report works offline.</footer></main></body></html>'
    Path(args.html).parent.mkdir(parents=True,exist_ok=True)
    Path(args.html).write_text(doc,encoding="utf-8")
    print(f"HTML report: {args.html}")
    print(f"Summary CSV: {args.summary_csv}")
    print(f"Rows: {len(rows)} | OK: {ok} | Unavailable/Skipped: {unavailable} | Failed: {failed}")
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as exc:
        print(f"Report generation error: {exc}",file=sys.stderr); raise SystemExit(2)

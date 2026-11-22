"""Dependency-free interaction card for the explicitly synthetic globe exercise."""

from html import escape
import json

import streamlit as st


def scenario_card_html(scenario, stage_index, scenarios=None):
    """Return an accessible draggable card with a tether and spring-back behavior."""
    stage = scenario.steps[stage_index]
    scenarios = scenarios or (scenario,)
    scenario_data = json.dumps([
        {
            "name": item.name,
            "route": f"{item.origin_name} → {item.destination_name}",
            "stage": item.steps[stage_index],
            "response": item.outcome,
        }
        for item in scenarios
    ], ensure_ascii=True).replace("</", "<\\/")
    return f"""
    <div id="scenario-card-root" class="interaction" aria-label="Synthetic scenario inspection card">
      <div class="tether-line" aria-hidden="true"></div>
      <div id="card" class="card" tabindex="0" role="group"
           aria-label="Draggable synthetic scenario details. Use arrow keys to move and Escape to reset.">
        <span class="eyebrow">SYNTHETIC TABLETOP · STAGE {stage_index + 1} OF 4</span>
        <strong id="scenario-title">{escape(scenario.name)}</strong>
        <dl>
          <div><dt>Route</dt><dd id="scenario-route">{escape(scenario.origin_name)} → {escape(scenario.destination_name)}</dd></div>
          <div><dt>Activity</dt><dd id="scenario-stage">{escape(stage)}</dd></div>
          <div><dt>Response</dt><dd id="scenario-response">{escape(scenario.outcome)}</dd></div>
        </dl>
        <p>Drag this card—not the geographical anchors. This exercise is unrelated to model predictions.</p>
        <button type="button">Reset card position</button>
      </div>
      <div id="status" class="sr" aria-live="polite">Card at its starting position.</div>
    </div>
    <style>
      #scenario-card-root, #scenario-card-root * {{ box-sizing:border-box; }}
      #scenario-card-root {{ color-scheme:dark; font-family:Inter,"Segoe UI",system-ui,sans-serif; color:#e8f0f8; }}
      .interaction {{ position:relative; min-height:238px; border:1px solid #24384c; border-radius:10px;
        background:linear-gradient(135deg,#0b1725,#0d1d2b); overflow:hidden; touch-action:none; }}
      .interaction:before {{ content:"DRAGGABLE INSPECTION CARD"; position:absolute; left:18px; top:18px;
        color:#7890a7; font-size:10px; font-weight:800; letter-spacing:.14em; }}
      .tether-line {{ position:absolute; left:52px; top:115px; width:128px; height:2px; transform-origin:0 50%;
        background:repeating-linear-gradient(90deg,#35d7c1 0 4px,transparent 4px 9px); opacity:.65; pointer-events:none; }}
      .card {{ position:absolute; left:180px; top:35px; width:min(520px,calc(100% - 205px)); padding:16px;
        border:1px solid #36536d; border-left:3px solid #35d7c1; border-radius:9px; background:#101f30;
        box-shadow:0 12px 30px rgba(0,0,0,.3); cursor:grab; user-select:none; outline:none; }}
      .card:active {{ cursor:grabbing; }} .card:focus-visible {{ outline:2px solid #35d7c1; outline-offset:3px; }}
      .eyebrow {{ display:block; color:#35d7c1; font-size:10px; font-weight:800; letter-spacing:.12em; margin-bottom:5px; }}
      .card>strong {{ display:block; font-size:17px; margin-bottom:9px; }}
      dl {{ display:grid; gap:5px; margin:0; }} dl div {{ display:grid; grid-template-columns:72px 1fr; gap:8px; }}
      dt {{ color:#8194aa; font-size:11px; }} dd {{ color:#dce6ee; font-size:12px; margin:0; }}
      p {{ color:#91a4b6; font-size:11px; line-height:1.45; margin:9px 0; }}
      button {{ min-height:44px; padding:8px 12px; border:1px solid #38536c; border-radius:7px;
        background:#14283a; color:#dffbf4; font-weight:700; cursor:pointer; }}
      button:hover {{ border-color:#35d7c1; }} button:focus-visible {{ outline:2px solid #35d7c1; outline-offset:2px; }}
      .sr {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); }}
      @media(max-width:640px) {{
        .interaction {{ min-height:286px; touch-action:auto; }} .interaction:before {{ left:12px; top:12px; }}
        .tether-line {{ display:none; }} .card {{ left:12px; top:38px; width:calc(100% - 24px); cursor:default; }}
      }}
      @media(prefers-reduced-motion:reduce) {{ .card {{ transition:none!important; }} }}
    </style>
    <script>
    (() => {{
      const componentRoot = document.currentScript.parentElement.querySelector('#scenario-card-root');
      const card = componentRoot.querySelector('#card');
      const line = componentRoot.querySelector('.tether-line');
      const status = componentRoot.querySelector('#status');
      const resetButton = componentRoot.querySelector('button');
      const scenarios = {scenario_data};
      let dx = 0, dy = 0, startX = 0, startY = 0, dragging = false;
      let resizeTimer;
      const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
      const draw = () => {{
        card.style.transform = `translate(${{dx}}px, ${{dy}}px)`;
        const vx = 128 + dx, vy = dy;
        line.style.width = `${{Math.hypot(vx, vy)}}px`;
        line.style.transform = `rotate(${{Math.atan2(vy, vx)}}rad)`;
      }};
      const reset = () => {{
        card.style.transition = reduced ? 'none' : 'transform 420ms cubic-bezier(.2,.9,.3,1.25)';
        dx = 0; dy = 0; draw(); status.textContent = 'Card returned to its starting position.';
        setTimeout(() => card.style.transition = '', reduced ? 0 : 430);
      }};
      card.addEventListener('pointerdown', event => {{
        if (innerWidth <= 640 || event.target.tagName === 'BUTTON') return;
        dragging = true; startX = event.clientX - dx; startY = event.clientY - dy; card.setPointerCapture(event.pointerId);
      }});
      card.addEventListener('pointermove', event => {{
        if (!dragging) return; dx = event.clientX - startX; dy = event.clientY - startY; draw();
      }});
      card.addEventListener('pointerup', () => {{ if (dragging) {{ dragging = false; reset(); }} }});
      card.addEventListener('keydown', event => {{
        const step = event.shiftKey ? 20 : 8;
        if (event.key === 'Escape') {{ reset(); return; }}
        if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) return;
        event.preventDefault();
        if (event.key === 'ArrowLeft') dx -= step; if (event.key === 'ArrowRight') dx += step;
        if (event.key === 'ArrowUp') dy -= step; if (event.key === 'ArrowDown') dy += step;
        draw(); status.textContent = 'Card moved. Press Escape to reset.';
      }});
      resetButton.addEventListener('click', reset);
      const startGlobeMotion = (attempt = 0) => {{
        const charts = [...document.querySelectorAll('[data-testid="stPlotlyChart"]')];
        const globe = charts.at(-1);
        const paths = globe && [...globe.querySelectorAll('g.trace.scattergeo path.js-line')].slice(0, 3);
        if (paths?.length === 3 && globe.querySelector('circle[data-sentinel-signal]')) {{
          globe.__sentinelRedraw?.(); return;
        }}
        if (paths?.length === 3) {{
          globe.dataset.sentinelMotionStarted = 'true';
          const namespace = 'http://www.w3.org/2000/svg';
          const durations = [5200, 6100, 7000];
          const offsets = [0, .31, .63];
          const signals = paths.map((path, index) => {{
            const signal = document.createElementNS(namespace, 'circle');
            signal.setAttribute('data-sentinel-signal', String(index));
            signal.setAttribute('r', '5'); signal.setAttribute('fill', '#ff5b73');
            signal.setAttribute('stroke', '#071018'); signal.setAttribute('stroke-width', '1.5');
            signal.setAttribute('tabindex', '0'); signal.setAttribute('role', 'button');
            signal.setAttribute('aria-label', `Inspect ${{scenarios[index].name}} synthetic signal`);
            signal.style.cursor = 'pointer'; signal.style.pointerEvents = 'all';
            const title = document.createElementNS(namespace, 'title');
            title.textContent = `${{scenarios[index].name}}: ${{scenarios[index].route}} · ${{scenarios[index].stage}}`;
            signal.appendChild(title); path.parentElement.appendChild(signal);
            return signal;
          }});
          const inspect = index => {{
            const item = scenarios[index];
            componentRoot.querySelector('#scenario-title').textContent = item.name;
            componentRoot.querySelector('#scenario-route').textContent = item.route;
            componentRoot.querySelector('#scenario-stage').textContent = item.stage;
            componentRoot.querySelector('#scenario-response').textContent = item.response;
            paths.forEach((path, routeIndex) => {{
              path.style.stroke = routeIndex === index ? '#ff5b73' : '#4b718e';
              path.style.strokeWidth = routeIndex === index ? '4px' : '1.6px';
              path.style.opacity = routeIndex === index ? '1' : '.55';
            }});
            status.textContent = `${{item.name}} selected for inspection.`;
          }};
          paths.forEach((path, index) => {{
            path.style.cursor = 'pointer'; path.addEventListener('click', () => inspect(index));
            signals[index].addEventListener('click', () => inspect(index));
            signals[index].addEventListener('keydown', event => {{
              if (event.key === 'Enter' || event.key === ' ') {{ event.preventDefault(); inspect(index); }}
            }});
          }});
          const plot = globe.querySelector('.js-plotly-plot');
          if (plot?.on && !plot.__sentinelAfterplotBound) {{
            plot.__sentinelAfterplotBound = true;
            plot.on('plotly_afterplot', () => requestAnimationFrame(() => {{
              if (!document.contains(componentRoot)) return;
              if (globe.querySelector('circle[data-sentinel-signal]')) globe.__sentinelRedraw?.();
              else startGlobeMotion();
            }}));
          }}
          const animate = now => {{
            if (!document.contains(globe)) return;
            if (signals.some(signal => !signal.isConnected)) {{ startGlobeMotion(); return; }}
            paths.forEach((path, index) => {{
              // Routes behind the globe's horizon are clipped to an empty path by Plotly.
              const length = path.getAttribute('d') ? path.getTotalLength() : 0;
              signals[index].style.display = length > 0 ? '' : 'none';
              if (!(length > 0)) return;
              const progress = reduced ? offsets[index] : ((now / durations[index]) + offsets[index]) % 1;
              const point = path.getPointAtLength(length * progress);
              signals[index].setAttribute('cx', String(point.x));
              signals[index].setAttribute('cy', String(point.y));
            }});
            if (!reduced) requestAnimationFrame(animate);
          }};
          // Reduced motion draws a single static frame, so redraw it after Plotly rotates or resizes.
          globe.__sentinelRedraw = reduced ? () => requestAnimationFrame(animate) : null;
          requestAnimationFrame(animate);
          status.textContent = 'Synthetic route motion started automatically.';
          return;
        }}
        if (attempt < 120) requestAnimationFrame(() => startGlobeMotion(attempt + 1));
      }};
      const restoreAfterResize = () => {{
        clearTimeout(resizeTimer);
        if (!document.contains(componentRoot)) {{ window.removeEventListener('resize', restoreAfterResize); return; }}
        resizeTimer = setTimeout(() => startGlobeMotion(), 350);
      }};
      window.addEventListener('resize', restoreAfterResize, {{passive:true}});
      startGlobeMotion();
    }})();
    </script>
    """


def render_scenario_card(scenario, stage_index, scenarios=None):
    st.html(scenario_card_html(scenario, stage_index, scenarios), unsafe_allow_javascript=True)

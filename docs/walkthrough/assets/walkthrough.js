/* Renders mermaid diagrams and provides a zoom/pan lightbox for them. */

(function () {
  var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;

  mermaid.initialize({
    startOnLoad: false,
    theme: dark ? "dark" : "default",
    flowchart: { useMaxWidth: true },
    sequence: { useMaxWidth: true }
  });

  mermaid.run({ querySelector: ".mermaid" }).then(attachLightbox, attachLightbox);

  function attachLightbox() {
    document.querySelectorAll("figure.diagram").forEach(function (fig) {
      fig.addEventListener("click", function () {
        var svg = fig.querySelector("svg");
        if (svg) openLightbox(svg);
      });
    });
  }

  var box = document.getElementById("lightbox");
  var stage = document.getElementById("lightbox-stage");
  var closeBtn = document.getElementById("lightbox-close");
  var scale = 1, tx = 0, ty = 0, dragging = false, lastX = 0, lastY = 0, current = null;

  function apply() {
    if (current) {
      current.style.transform =
        "translate(" + tx + "px," + ty + "px) scale(" + scale + ")";
    }
  }

  function openLightbox(svg) {
    stage.innerHTML = "";
    current = svg.cloneNode(true);
    current.style.maxWidth = "none";
    // Pin the clone at the stage origin at its natural (viewBox) size,
    // then fit it to ~90% of the stage via the shared transform.
    var vb = current.viewBox && current.viewBox.baseVal;
    if (vb && vb.width) {
      current.setAttribute("width", vb.width);
      current.setAttribute("height", vb.height);
    }
    stage.style.position = "relative";
    current.style.position = "absolute";
    current.style.top = "0";
    current.style.left = "0";
    stage.appendChild(current);
    box.hidden = false;
    document.body.style.overflow = "hidden";

    var r = current.getBoundingClientRect();
    var s = stage.getBoundingClientRect();
    scale = Math.min((s.width * 0.9) / r.width, (s.height * 0.9) / r.height, 3);
    if (!isFinite(scale) || scale <= 0) scale = 1;
    tx = (s.width - r.width * scale) / 2;
    ty = (s.height - r.height * scale) / 2;
    apply();
  }

  function closeLightbox() {
    box.hidden = true;
    stage.innerHTML = "";
    current = null;
    document.body.style.overflow = "";
  }

  closeBtn.addEventListener("click", closeLightbox);
  box.addEventListener("click", function (e) {
    if (e.target === box) closeLightbox();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !box.hidden) closeLightbox();
  });

  stage.addEventListener("wheel", function (e) {
    if (!current) return;
    e.preventDefault();
    var factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    var next = Math.min(Math.max(scale * factor, 0.2), 12);
    var rect = stage.getBoundingClientRect();
    var px = e.clientX - rect.left, py = e.clientY - rect.top;
    // Zoom toward the cursor position.
    tx = px - ((px - tx) / scale) * next;
    ty = py - ((py - ty) / scale) * next;
    scale = next;
    apply();
  }, { passive: false });

  stage.addEventListener("mousedown", function (e) {
    if (!current) return;
    dragging = true;
    lastX = e.clientX;
    lastY = e.clientY;
    e.preventDefault();
  });
  window.addEventListener("mousemove", function (e) {
    if (!dragging) return;
    tx += e.clientX - lastX;
    ty += e.clientY - lastY;
    lastX = e.clientX;
    lastY = e.clientY;
    apply();
  });
  window.addEventListener("mouseup", function () { dragging = false; });
})();

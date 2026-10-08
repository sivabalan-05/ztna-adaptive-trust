import { useEffect, useRef } from "react";

const REVEAL_SELECTOR = "[data-scroll-reveal]";

export default function MotionEffects() {
  const progressRef = useRef<HTMLDivElement>(null);
  const rippleLayerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const revealObserver = "IntersectionObserver" in window
      ? new IntersectionObserver((entries, observer) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add("motion-visible");
              observer.unobserve(entry.target);
            }
          });
        }, { threshold: 0.12, rootMargin: "0px 0px -36px 0px" })
      : null;

    const discoverRevealTargets = (root: ParentNode) => {
      root.querySelectorAll(REVEAL_SELECTOR).forEach((target) => {
        if (target.classList.contains("motion-observed")) return;
        target.classList.add("motion-observed");
        if (reducedMotion.matches || !revealObserver) {
          target.classList.add("motion-visible");
        } else {
          revealObserver.observe(target);
        }
      });
    };

    document.body.classList.add("motion-ready");
    discoverRevealTargets(document);
    const contentObserver = new MutationObserver((records) => {
      records.forEach((record) => record.addedNodes.forEach((node) => {
        if (node instanceof HTMLElement) {
          if (node.matches(REVEAL_SELECTOR)) discoverRevealTargets(node.parentNode ?? document);
          else discoverRevealTargets(node);
        }
      }));
    });
    contentObserver.observe(document.body, { childList: true, subtree: true });

    let progressFrame = 0;
    const updateProgress = () => {
      if (progressFrame) return;
      progressFrame = requestAnimationFrame(() => {
        const scrollable = document.documentElement.scrollHeight - window.innerHeight;
        const progress = scrollable > 0 ? window.scrollY / scrollable : 0;
        progressRef.current?.style.setProperty("transform", `scaleX(${progress})`);
        progressFrame = 0;
      });
    };
    const addRipple = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Element) || !target.closest("button, a, [role='button'], input[type='checkbox'], input[type='radio']")) return;
      const ripple = document.createElement("span");
      ripple.className = "tap-ripple";
      ripple.style.left = `${event.clientX}px`;
      ripple.style.top = `${event.clientY}px`;
      rippleLayerRef.current?.append(ripple);
      ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
    };

    if (!reducedMotion.matches) {
      window.addEventListener("pointerdown", addRipple, { passive: true });
      window.addEventListener("scroll", updateProgress, { passive: true });
      window.addEventListener("resize", updateProgress, { passive: true });
    }
    reducedMotion.addEventListener("change", updateProgress);

    return () => {
      document.body.classList.remove("motion-ready");
      revealObserver?.disconnect();
      contentObserver.disconnect();
      window.removeEventListener("pointerdown", addRipple);
      window.removeEventListener("scroll", updateProgress);
      window.removeEventListener("resize", updateProgress);
      reducedMotion.removeEventListener("change", updateProgress);
      cancelAnimationFrame(progressFrame);
    };
  }, []);

  return (
    <div className="motion-effects" aria-hidden="true">
      <div className="scroll-progress" ref={progressRef} />
      <div className="ripple-layer" ref={rippleLayerRef} />
    </div>
  );
}

import { useEffect, useRef } from "react";

const REVEAL_SELECTOR = "[data-scroll-reveal]";

export default function MotionEffects() {
  const pointerRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef<HTMLDivElement>(null);
  const rippleLayerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const finePointer = window.matchMedia("(pointer: fine)");
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

    let pointerFrame = 0;
    let progressFrame = 0;
    let pointerX = 0;
    let pointerY = 0;
    const interactiveSelector = "button, a, [role='button'], input, select, textarea, label";
    const updatePointer = (event: PointerEvent) => {
      pointerX = event.clientX;
      pointerY = event.clientY;
      const cursor = pointerRef.current;
      cursor?.classList.add("cursor-visible");
      cursor?.classList.toggle("cursor-hovering", event.target instanceof Element && !!event.target.closest(interactiveSelector));
      if (pointerFrame) return;
      pointerFrame = requestAnimationFrame(() => {
        cursor?.style.setProperty("transform", `translate3d(${pointerX}px, ${pointerY}px, 0)`);
        pointerFrame = 0;
      });
    };
    const hidePointer = () => pointerRef.current?.classList.remove("cursor-visible");
    const pressPointer = () => pointerRef.current?.classList.add("cursor-pressed");
    const releasePointer = () => pointerRef.current?.classList.remove("cursor-pressed");
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

    if (finePointer.matches) {
      window.addEventListener("pointermove", updatePointer, { passive: true });
      window.addEventListener("pointerleave", hidePointer);
      window.addEventListener("pointerdown", pressPointer, { passive: true });
      window.addEventListener("pointerup", releasePointer, { passive: true });
    }
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
      window.removeEventListener("pointermove", updatePointer);
      window.removeEventListener("pointerleave", hidePointer);
      window.removeEventListener("pointerdown", pressPointer);
      window.removeEventListener("pointerup", releasePointer);
      window.removeEventListener("pointerdown", addRipple);
      window.removeEventListener("scroll", updateProgress);
      window.removeEventListener("resize", updateProgress);
      reducedMotion.removeEventListener("change", updateProgress);
      cancelAnimationFrame(pointerFrame);
      cancelAnimationFrame(progressFrame);
    };
  }, []);

  return (
    <div className="motion-effects" aria-hidden="true">
      <div className="scroll-progress" ref={progressRef} />
      <div className="custom-cursor" ref={pointerRef}>
        <span className="cursor-ring" />
        <span className="cursor-center" />
      </div>
      <div className="ripple-layer" ref={rippleLayerRef} />
    </div>
  );
}

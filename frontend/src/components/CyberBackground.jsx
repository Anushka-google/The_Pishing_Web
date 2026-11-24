import React, { useEffect, useRef } from 'react';

/**
 * CyberBackground
 * Cinematic, GPU-friendly animated cyber neural network canvas.
 * Renders floating encrypted data particles, interconnected network nodes,
 * and glowing cyan/blue atmospheric depth with interactive mouse parallax.
 */
export default function CyberBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    // Mouse coordinates with smoothing
    const mouse = { x: width / 2, y: height / 2, targetX: width / 2, targetY: height / 2 };

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    const handleMouseMove = (e) => {
      mouse.targetX = e.clientX;
      mouse.targetY = e.clientY;
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove, { passive: true });

    // Particle nodes count calibrated for performance
    const particleCount = Math.min(Math.floor((width * height) / 18000), 75);
    const particles = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        radius: Math.random() * 1.8 + 0.8,
        color: Math.random() > 0.35 ? '#00e5ff' : '#1677ff',
        alpha: Math.random() * 0.5 + 0.2,
        pulseSpeed: Math.random() * 0.02 + 0.008,
        pulseAngle: Math.random() * Math.PI * 2
      });
    }

    // Binary code stream particles
    const dataStreamCount = 12;
    const streams = [];
    const hexChars = '01ABCDEF01';
    for (let i = 0; i < dataStreamCount; i++) {
      streams.push({
        x: Math.random() * width,
        y: Math.random() * height,
        speed: Math.random() * 0.7 + 0.3,
        text: hexChars[Math.floor(Math.random() * hexChars.length)],
        alpha: Math.random() * 0.25 + 0.05,
        size: Math.floor(Math.random() * 4) + 9
      });
    }

    let isVisible = true;
    const handleVisibility = () => {
      isVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', handleVisibility);

    // Check reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const render = () => {
      if (!isVisible) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      // Smooth mouse follow
      mouse.x += (mouse.targetX - mouse.x) * 0.05;
      mouse.y += (mouse.targetY - mouse.y) * 0.05;

      ctx.clearRect(0, 0, width, height);

      // Render subtle data streams
      ctx.font = '10px "JetBrains Mono", monospace';
      for (let s of streams) {
        ctx.fillStyle = `rgba(0, 229, 255, ${s.alpha})`;
        ctx.fillText(s.text, s.x, s.y);
        if (!prefersReducedMotion) {
          s.y += s.speed;
          if (s.y > height + 20) {
            s.y = -10;
            s.x = Math.random() * width;
            s.text = hexChars[Math.floor(Math.random() * hexChars.length)];
          }
        }
      }

      // Draw connection lines between nearby particles
      const maxDistance = 140;
      for (let i = 0; i < particles.length; i++) {
        const p1 = particles[i];

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const lineAlpha = (1 - dist / maxDistance) * 0.22;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(0, 229, 255, ${lineAlpha})`;
            ctx.lineWidth = 0.65;
            ctx.stroke();
          }
        }

        // Slight mouse attraction/displacement
        const mdx = mouse.x - p1.x;
        const mdy = mouse.y - p1.y;
        const mDist = Math.sqrt(mdx * mdx + mdy * mdy);
        if (mDist < 180 && !prefersReducedMotion) {
          const force = (1 - mDist / 180) * 0.6;
          p1.x -= (mdx / mDist) * force;
          p1.y -= (mdy / mDist) * force;
        }

        // Particle pulse
        p1.pulseAngle += p1.pulseSpeed;
        const currentAlpha = p1.alpha + Math.sin(p1.pulseAngle) * 0.15;

        // Draw particle node
        ctx.beginPath();
        ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
        ctx.fillStyle = p1.color === '#00e5ff' 
          ? `rgba(0, 229, 255, ${Math.max(0.1, currentAlpha)})`
          : `rgba(22, 119, 255, ${Math.max(0.1, currentAlpha)})`;
        ctx.shadowColor = p1.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Update positions
        if (!prefersReducedMotion) {
          p1.x += p1.vx;
          p1.y += p1.vy;

          if (p1.x < -10) p1.x = width + 10;
          if (p1.x > width + 10) p1.x = -10;
          if (p1.y < -10) p1.y = height + 10;
          if (p1.y > height + 10) p1.y = -10;
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.75
      }}
    />
  );
}

import React, { useEffect, useRef, useState } from 'react';
import { Shield, Cpu, Activity, Radio, Lock, Zap } from 'lucide-react';

/**
 * CyberThreatHolo3D
 * Signature 3D AI Cyber Defense Holographic Visualizer.
 * Renders an interactive 3D particle neural intelligence structure / AI cyber shield,
 * concentric rotating security rings with cyan and magenta energy accents,
 * orbiting data nodes, and four floating holographic intelligence telemetry panels.
 */
export default function CyberThreatHolo3D({ onScanClick, onExploreClick }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const [pulseTick, setPulseTick] = useState(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId;
    const width = (canvas.width = 500);
    const height = (canvas.height = 500);

    // 3D rotation angles & smooth mouse targets
    let rotX = 0.25;
    let rotY = 0;
    let targetRotX = 0.25;
    let targetRotY = 0;

    const handleMouseMove = (e) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const mouseX = e.clientX - rect.left - rect.width / 2;
      const mouseY = e.clientY - rect.top - rect.height / 2;

      targetRotY = (mouseX / (rect.width / 2)) * 0.7;
      targetRotX = 0.25 + (-mouseY / (rect.height / 2)) * 0.5;
    };

    const container = containerRef.current;
    if (container) {
      container.addEventListener('mousemove', handleMouseMove, { passive: true });
    }

    // 1. Procedural 3D AI Neural Face & Security Shield Geometry
    // We construct a point lattice forming an abstract cybernetic AI head contour & neural mesh
    const neuralPoints = [];
    
    // Front face silhouette points (forehead, eye sockets, cheekbones, jaw, chin, temple)
    const faceContour = [
      // Forehead & Brow
      { x: 0, y: -85, z: 25 },
      { x: -35, y: -75, z: 20 }, { x: 35, y: -75, z: 20 },
      { x: -60, y: -60, z: 5 }, { x: 60, y: -60, z: 5 },
      // Temples & Eyes
      { x: -40, y: -45, z: 32 }, { x: -20, y: -45, z: 38 }, // Left eye
      { x: 20, y: -45, z: 38 }, { x: 40, y: -45, z: 32 },   // Right eye
      { x: 0, y: -45, z: 35 },                                // Glabella
      // Nose bridge & Tip
      { x: 0, y: -25, z: 46 },
      { x: 0, y: -5, z: 54 },
      { x: -16, y: -2, z: 40 }, { x: 16, y: -2, z: 40 },     // Nostrils
      // Cheekbones & Midface
      { x: -55, y: -25, z: 25 }, { x: 55, y: -25, z: 25 },
      { x: -68, y: -5, z: 12 }, { x: 68, y: -5, z: 12 },
      // Mouth & Philtrum
      { x: 0, y: 15, z: 45 },
      { x: -25, y: 22, z: 36 }, { x: 25, y: 22, z: 36 },
      // Jawline & Chin
      { x: -45, y: 40, z: 20 }, { x: 45, y: 40, z: 20 },
      { x: -22, y: 60, z: 28 }, { x: 22, y: 60, z: 28 },
      { x: 0, y: 70, z: 34 },                                 // Chin apex
      // Cranium / Neural crown
      { x: 0, y: -110, z: -10 },
      { x: -45, y: -100, z: -20 }, { x: 45, y: -100, z: -20 },
      { x: -70, y: -75, z: -25 }, { x: 70, y: -75, z: -25 },
      { x: -75, y: -30, z: -30 }, { x: 75, y: -30, z: -30 },
      { x: -60, y: 15, z: -25 }, { x: 60, y: 15, z: -25 }
    ];

    faceContour.forEach((pt, i) => {
      neuralPoints.push({
        x: pt.x * 1.15,
        y: pt.y * 1.15,
        z: pt.z * 1.15,
        color: i % 3 === 0 ? '#ff2e93' : '#00d9ff',
        size: 2.2,
        isCore: true
      });
    });

    // Neural lattice connections between face nodes
    const faceEdges = [];
    for (let i = 0; i < neuralPoints.length; i++) {
      for (let j = i + 1; j < neuralPoints.length; j++) {
        const p1 = neuralPoints[i];
        const p2 = neuralPoints[j];
        const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y, p1.z - p2.z);
        if (dist < 46) {
          faceEdges.push([i, j]);
        }
      }
    }

    // 2. Concentric Cybernetic Shield Rings (Latitude & Longitude)
    const sphereRadius = 145;
    const ringPtsA = []; // Horizontal Equator Ring
    const ringPtsB = []; // Tilted Ring (Magenta)
    const ringPtsC = []; // Tilted Ring (Cyan)
    const segs = 36;
    for (let s = 0; s <= segs; s++) {
      const angle = (s / segs) * Math.PI * 2;
      // Ring A
      ringPtsA.push({
        x: sphereRadius * Math.cos(angle),
        y: sphereRadius * 0.15 * Math.sin(angle),
        z: sphereRadius * Math.sin(angle)
      });
      // Ring B (tilted ~45 deg)
      ringPtsB.push({
        x: (sphereRadius + 12) * Math.cos(angle),
        y: (sphereRadius + 12) * Math.sin(angle) * Math.cos(Math.PI / 4),
        z: (sphereRadius + 12) * Math.sin(angle) * Math.sin(Math.PI / 4)
      });
      // Ring C (tilted -45 deg)
      ringPtsC.push({
        x: (sphereRadius + 20) * Math.cos(angle) * Math.cos(Math.PI / 5),
        y: -(sphereRadius + 20) * Math.sin(angle),
        z: (sphereRadius + 20) * Math.cos(angle) * Math.sin(Math.PI / 5)
      });
    }

    // 3. Orbiting Data Interceptors (Satellites)
    const interceptors = [
      { radius: 175, speed: 0.022, angle: 0, tilt: 0.4, color: '#00d9ff', label: 'NODE-01' },
      { radius: 185, speed: -0.018, angle: 2.1, tilt: -0.5, color: '#ff2e93', label: 'THREAT-INT' },
      { radius: 195, speed: 0.015, angle: 4.2, tilt: 0.2, color: '#22c55e', label: 'VERIFIED' }
    ];

    // 3D Projection math
    const fov = 420;
    const project = (x, y, z) => {
      // Rotation around X
      const y1 = y * Math.cos(rotX) - z * Math.sin(rotX);
      const z1 = y * Math.sin(rotX) + z * Math.cos(rotX);

      // Rotation around Y
      const x2 = x * Math.cos(rotY) + z1 * Math.sin(rotY);
      const z2 = -x * Math.sin(rotY) + z1 * Math.cos(rotY);

      // Perspective projection
      const distance = 480;
      const scale = fov / (distance + z2);
      const px = width / 2 + x2 * scale;
      const py = height / 2 + y1 * scale;

      return { x: px, y: py, z: z2, scale };
    };

    let tick = 0;
    const render = () => {
      tick++;

      // Smooth rotate towards target
      rotX += (targetRotX - rotX) * 0.06;
      rotY += 0.008 + (targetRotY - rotY) * 0.06;

      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;

      // Outer HUD Cyber Radar Arc
      ctx.save();
      ctx.translate(cx, cy);

      // Dashed outer targeting circle
      ctx.beginPath();
      ctx.arc(0, 0, 215, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 217, 255, 0.12)';
      ctx.lineWidth = 1;
      ctx.setLineDash([6, 12]);
      ctx.stroke();

      // Rotating cyan radar sweep
      ctx.beginPath();
      const rStart = (tick * 0.025) % (Math.PI * 2);
      ctx.arc(0, 0, 215, rStart, rStart + 0.55);
      ctx.strokeStyle = '#00d9ff';
      ctx.lineWidth = 2.5;
      ctx.setLineDash([]);
      ctx.stroke();

      // Magenta counter-arc
      ctx.beginPath();
      const mStart = (-tick * 0.018) % (Math.PI * 2);
      ctx.arc(0, 0, 222, mStart, mStart + 0.45);
      ctx.strokeStyle = '#ff2e93';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Four Corner Tech Brackets
      const bDist = 228;
      const bLen = 14;
      const corners = [
        [-bDist, -bDist, 1, 1],
        [bDist, -bDist, -1, 1],
        [-bDist, bDist, 1, -1],
        [bDist, bDist, -1, -1]
      ];
      ctx.strokeStyle = 'rgba(0, 217, 255, 0.45)';
      ctx.lineWidth = 1.5;
      for (const [bx, by, dx, dy] of corners) {
        ctx.beginPath();
        ctx.moveTo(bx, by + dy * bLen);
        ctx.lineTo(bx, by);
        ctx.lineTo(bx + dx * bLen, by);
        ctx.stroke();
      }
      ctx.restore();

      // Central ambient glow gradient
      const radGlow = ctx.createRadialGradient(cx, cy, 10, cx, cy, 150);
      radGlow.addColorStop(0, 'rgba(0, 217, 255, 0.18)');
      radGlow.addColorStop(0.4, 'rgba(255, 46, 147, 0.08)');
      radGlow.addColorStop(1, 'transparent');
      ctx.fillStyle = radGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, 150, 0, Math.PI * 2);
      ctx.fill();

      // Draw Rotating Shield Rings (Back segments first or with alpha blend)
      const drawRing = (pts, strokeStyle, width) => {
        ctx.beginPath();
        let first = true;
        for (const pt of pts) {
          const p = project(pt.x, pt.y, pt.z);
          if (first) {
            ctx.moveTo(p.x, p.y);
            first = false;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.strokeStyle = strokeStyle;
        ctx.lineWidth = width;
        ctx.stroke();
      };

      drawRing(ringPtsA, 'rgba(0, 217, 255, 0.28)', 1);
      drawRing(ringPtsB, 'rgba(255, 46, 147, 0.28)', 1.2);
      drawRing(ringPtsC, 'rgba(52, 120, 255, 0.24)', 1);

      // Draw Neural Lattice Edges (Lines between AI face points)
      for (const [i1, i2] of faceEdges) {
        const p1 = project(neuralPoints[i1].x, neuralPoints[i1].y, neuralPoints[i1].z);
        const p2 = project(neuralPoints[i2].x, neuralPoints[i2].y, neuralPoints[i2].z);

        const zAvg = (p1.z + p2.z) / 2;
        const lineAlpha = zAvg > 0 ? 0.45 : 0.15;

        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = `rgba(0, 217, 255, ${lineAlpha})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // Draw Neural AI Points
      for (const np of neuralPoints) {
        const proj = project(np.x, np.y, np.z);
        const pSize = (proj.z > 0 ? 3.2 : 1.8) * proj.scale;

        ctx.beginPath();
        ctx.arc(proj.x, proj.y, Math.max(1.2, pSize), 0, Math.PI * 2);
        ctx.fillStyle = np.color;
        if (proj.z > 0) {
          ctx.shadowColor = np.color;
          ctx.shadowBlur = 8;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Draw Orbiting Interceptors & Laser Beams
      for (const inc of interceptors) {
        inc.angle += inc.speed;
        const ix = inc.radius * Math.cos(inc.angle);
        const iy = inc.radius * Math.sin(inc.angle) * Math.cos(inc.tilt);
        const iz = inc.radius * Math.sin(inc.angle) * Math.sin(inc.tilt);

        const ip = project(ix, iy, iz);

        // Draw laser connector line to AI core
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(ip.x, ip.y);
        ctx.strokeStyle = `${inc.color}${ip.z > 0 ? '55' : '18'}`;
        ctx.lineWidth = 0.8;
        ctx.stroke();

        // Node circle
        const nSize = (ip.z > 0 ? 4.5 : 2.5) * ip.scale;
        ctx.beginPath();
        ctx.arc(ip.x, ip.y, Math.max(2, nSize), 0, Math.PI * 2);
        ctx.fillStyle = inc.color;
        ctx.shadowColor = inc.color;
        ctx.shadowBlur = ip.z > 0 ? 14 : 5;
        ctx.fill();
        ctx.shadowBlur = 0;

        // HUD target bracket for front nodes
        if (ip.z > 0) {
          ctx.strokeStyle = `${inc.color}aa`;
          ctx.lineWidth = 1;
          ctx.strokeRect(ip.x - 8, ip.y - 8, 16, 16);

          ctx.font = '8px "JetBrains Mono", monospace';
          ctx.fillStyle = inc.color;
          ctx.fillText(inc.label, ip.x + 10, ip.y - 4);
        }
      }

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      if (container) {
        container.removeEventListener('mousemove', handleMouseMove);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={{
        position: 'relative',
        width: '100%',
        maxWidth: '520px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}
    >
      {/* Central 3D Canvas */}
      <canvas
        ref={canvasRef}
        style={{
          width: '100%',
          maxWidth: '500px',
          height: 'auto',
          aspectRatio: '1 / 1',
          display: 'block',
          filter: 'drop-shadow(0 0 35px rgba(0, 217, 255, 0.25))',
          cursor: 'crosshair',
          position: 'relative',
          zIndex: 2
        }}
      />

      {/* FLOATING HOLOGRAPHIC PANEL A: Real-Time Threat Monitor (Top-Left) */}
      <div
        style={{
          position: 'absolute',
          top: '20px',
          left: '-20px',
          background: 'rgba(8, 13, 25, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 217, 255, 0.35)',
          borderRadius: '10px',
          padding: '0.65rem 0.95rem',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6), 0 0 15px rgba(0, 217, 255, 0.15)',
          zIndex: 3,
          maxWidth: '190px',
          fontSize: '0.72rem',
          fontFamily: 'JetBrains Mono, monospace'
        }}
        className="cyber-corners"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.25rem' }}>
          <Radio size={13} color="#00d9ff" className="animate-pulse" />
          <span style={{ color: '#00d9ff', fontWeight: '800', letterSpacing: '0.04em' }}>THREAT MONITOR</span>
        </div>
        <div style={{ color: '#f8fafc', fontWeight: '700' }}>STATE: ARMED</div>
        <div style={{ color: '#94a3b8', fontSize: '0.65rem' }}>Latency: 0.29 ms • Live</div>
      </div>

      {/* FLOATING HOLOGRAPHIC PANEL B: URL Structural Analysis (Top-Right) */}
      <div
        style={{
          position: 'absolute',
          top: '30px',
          right: '-20px',
          background: 'rgba(8, 13, 25, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(255, 46, 147, 0.35)',
          borderRadius: '10px',
          padding: '0.65rem 0.95rem',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6), 0 0 15px rgba(255, 46, 147, 0.15)',
          zIndex: 3,
          maxWidth: '190px',
          fontSize: '0.72rem',
          fontFamily: 'JetBrains Mono, monospace'
        }}
        className="cyber-corners cyber-corners-magenta"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.25rem' }}>
          <Cpu size={13} color="#ff2e93" />
          <span style={{ color: '#ff2e93', fontWeight: '800', letterSpacing: '0.04em' }}>STRUCTURAL AI</span>
        </div>
        <div style={{ color: '#f8fafc', fontWeight: '700' }}>22 LEXICAL RFCs</div>
        <div style={{ color: '#94a3b8', fontSize: '0.65rem' }}>Shannon Entropy Analyzed</div>
      </div>

      {/* FLOATING HOLOGRAPHIC PANEL C: AI Detection Engine (Bottom-Left) */}
      <div
        style={{
          position: 'absolute',
          bottom: '25px',
          left: '-15px',
          background: 'rgba(8, 13, 25, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(52, 120, 255, 0.35)',
          borderRadius: '10px',
          padding: '0.65rem 0.95rem',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6), 0 0 15px rgba(52, 120, 255, 0.15)',
          zIndex: 3,
          maxWidth: '190px',
          fontSize: '0.72rem',
          fontFamily: 'JetBrains Mono, monospace'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.25rem' }}>
          <Lock size={13} color="#3478ff" />
          <span style={{ color: '#3478ff', fontWeight: '800', letterSpacing: '0.04em' }}>ZERO-LEAKAGE</span>
        </div>
        <div style={{ color: '#f8fafc', fontWeight: '700' }}>GROUPSHUFFLESPLIT</div>
        <div style={{ color: '#94a3b8', fontSize: '0.65rem' }}>Domain-Group Disjoint</div>
      </div>

      {/* FLOATING HOLOGRAPHIC PANEL D: Threat Intelligence (Bottom-Right) */}
      <div
        style={{
          position: 'absolute',
          bottom: '20px',
          right: '-15px',
          background: 'rgba(8, 13, 25, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(34, 197, 94, 0.35)',
          borderRadius: '10px',
          padding: '0.65rem 0.95rem',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6), 0 0 15px rgba(34, 197, 94, 0.15)',
          zIndex: 3,
          maxWidth: '190px',
          fontSize: '0.72rem',
          fontFamily: 'JetBrains Mono, monospace'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.25rem' }}>
          <Activity size={13} color="#22c55e" />
          <span style={{ color: '#22c55e', fontWeight: '800', letterSpacing: '0.04em' }}>THREAT FEEDS</span>
        </div>
        <div style={{ color: '#f8fafc', fontWeight: '700' }}>MULTI-SIGNAL</div>
        <div style={{ color: '#94a3b8', fontSize: '0.65rem' }}>DNS + WHOIS + Reputation</div>
      </div>
    </div>
  );
}

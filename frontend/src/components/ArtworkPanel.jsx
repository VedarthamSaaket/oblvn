const C = "#f5ead0"
const BG = "#111a09"

function Art1() {
    return (
        <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%', display: 'block' }}>
            <rect width="300" height="400" fill={BG} />
            <defs>
                <filter id="ap-ch1">
                    <feTurbulence type="fractalNoise" baseFrequency="0.045" numOctaves="4" seed="2" result="n" />
                    <feDisplacementMap in="SourceGraphic" in2="n" scale="2.2" xChannelSelector="R" yChannelSelector="G" />
                </filter>
            </defs>
            <g filter="url(#ap-ch1)" fill={C} stroke={C}>
                <circle cx="150" cy="82" r="30" stroke="none" />
                <path d="M 75 160 A 75 75 0 0 0 225 160 Z" strokeWidth="3.5" strokeLinecap="round" />
                {[55, 63, 71, 79, 87, 95, 103, 111, 119, 127].map((x, i) => (
                    <path key={i} d={`M ${x} 370 A ${95 - i * 8} ${95 - i * 8} 0 0 1 ${245 - x + 55} 370`}
                        fill="none" strokeWidth={i < 2 ? 2.2 : i < 6 ? 2 : 1.8} />
                ))}
                <ellipse cx="150" cy="372" rx="95" ry="22" stroke="none" />
            </g>
        </svg>
    )
}

function Art2() {
    return (
        <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%', display: 'block' }}>
            <rect width="300" height="400" fill={BG} />
            <defs>
                <filter id="ap-ch2">
                    <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="4" seed="5" result="n" />
                    <feDisplacementMap in="SourceGraphic" in2="n" scale="2.2" xChannelSelector="R" yChannelSelector="G" />
                </filter>
            </defs>
            <g filter="url(#ap-ch2)" fill={C} stroke={C}>
                <circle cx="150" cy="105" r="72" strokeWidth="4" />
                <path d="M 70 215 A 80 80 0 0 0 230 215 Z" stroke="none" />
                {[78, 87, 96, 105, 114, 123, 132].map((x, i) => (
                    <path key={i} d={`M ${x} 215 A ${72 - i * 9} ${50 - i * 7} 0 0 1 ${222 - (x - 78)} 215`}
                        fill="none" strokeWidth="2.2" />
                ))}
                <path d="M 40 345 A 110 110 0 0 0 260 345 Z" stroke="none" />
                {[50, 62, 74, 86, 98, 110].map((x, i) => (
                    <path key={i} d={`M ${x} 345 A ${100 - i * 12} ${70 - i * 9} 0 0 1 ${250 - (x - 50)} 345`}
                        fill="none" strokeWidth="2.2" />
                ))}
            </g>
        </svg>
    )
}

function Art3() {
    return (
        <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%', display: 'block' }}>
            <rect width="300" height="400" fill={BG} />
            <defs>
                <filter id="ap-ch3">
                    <feTurbulence type="fractalNoise" baseFrequency="0.042" numOctaves="4" seed="9" result="n" />
                    <feDisplacementMap in="SourceGraphic" in2="n" scale="2.2" xChannelSelector="R" yChannelSelector="G" />
                </filter>
            </defs>
            <g filter="url(#ap-ch3)" fill="none" stroke={C} strokeLinecap="round">
                {[65, 76, 87, 98, 109, 120, 131, 142].map((x, i) => (
                    <path key={i} d={`M ${x} 60 L ${x} 280 A ${85 - i * 11} ${85 - i * 11} 0 0 0 ${235 - (x - 65)} 280 L ${235 - (x - 65)} 60`}
                        strokeWidth={i === 0 ? 2.5 : i < 3 ? 2.3 : i < 6 ? 2.2 : 2} />
                ))}
                <circle cx="162" cy="148" r="11" fill={C} stroke="none" />
                <path d="M 60 400 A 90 90 0 0 1 240 400 Z" fill={C} stroke="none" />
            </g>
        </svg>
    )
}

function Art4() {
    return (
        <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%', display: 'block' }}>
            <rect width="300" height="400" fill={BG} />
            <defs>
                <filter id="ap-ch4">
                    <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="4" seed="55" result="n" />
                    <feDisplacementMap in="SourceGraphic" in2="n" scale="2.5" xChannelSelector="R" yChannelSelector="G" />
                </filter>
            </defs>
            <g filter="url(#ap-ch4)" fill={C} stroke={C} strokeLinecap="round" strokeLinejoin="round">
                <circle cx="150" cy="88" r="55" stroke="none" />
                <circle cx="150" cy="88" r="55" fill="none" strokeWidth="4" />
                {[25, 38, 51, 64, 77, 90, 103, 116, 129, 142].map((x, i) => (
                    <path key={i} d={`M ${x} 330 L ${x} ${260 + i * 4} A ${125 - i * 13} ${125 - i * 13} 0 0 1 ${275 - (x - 25)} ${260 + i * 4} L ${275 - (x - 25)} 330`}
                        fill="none" strokeWidth={i < 2 ? 2.5 : i < 4 ? 2.3 : i < 7 ? 2 : 1.9} />
                ))}
                <path d="M0 360C55 345 120 352 180 347C235 342 268 352 300 347L300 400L0 400Z" stroke="none" />
                <path d="M0 360C55 345 120 352 180 347C235 342 268 352 300 347" fill="none" strokeWidth="2.5" />
                <circle cx="60" cy="145" r="8" stroke="none" />
                <circle cx="240" cy="175" r="6" stroke="none" />
            </g>
        </svg>
    )
}

function Art5() {
    return (
        <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%', display: 'block' }}>
            <rect width="300" height="400" fill={BG} />
            <defs>
                <filter id="ap-ch5">
                    <feTurbulence type="fractalNoise" baseFrequency="0.042" numOctaves="4" seed="77" result="n" />
                    <feDisplacementMap in="SourceGraphic" in2="n" scale="2.5" xChannelSelector="R" yChannelSelector="G" />
                </filter>
            </defs>
            <g filter="url(#ap-ch5)" fill={C} stroke={C} strokeLinecap="round" strokeLinejoin="round">
                {[30, 44, 58, 72, 86, 100, 114, 128, 142].map((x, i) => (
                    <path key={i} d={`M ${x} 400 L ${x} ${255 + i * 5} A ${120 - i * 13} ${120 - i * 13} 0 0 1 ${270 - (x - 30)} ${255 + i * 5} L ${270 - (x - 30)} 400`}
                        fill="none" strokeWidth={i < 2 ? 2.5 : i < 4 ? 2.3 : i < 6 ? 2.2 : i < 8 ? 1.9 : 1.7} />
                ))}
                <circle cx="150" cy="155" r="45" stroke="none" />
                <circle cx="150" cy="155" r="45" fill="none" strokeWidth="4" />
                <circle cx="162" cy="148" r="34" fill={BG} stroke="none" />
                <path d="M80 62A70 70 0 0 1 220 62Z" stroke="none" />
                <path d="M80 62A70 70 0 0 1 220 62Z" fill="none" strokeWidth="3" />
                <path d="M100 38A50 50 0 0 1 200 38Z" stroke="none" />
                <path d="M100 38A50 50 0 0 1 200 38Z" fill="none" strokeWidth="2.5" />
            </g>
        </svg>
    )
}

const ARTS = [Art1, Art2, Art3, Art4, Art5]

function ArtCard({ ArtComp, style }) {
    return (
        <div
            style={{
                position: 'absolute',
                border: '2px solid rgba(245,234,208,0.6)',
                outline: '1px solid rgba(245,234,208,0.15)',
                outlineOffset: '3px',
                overflow: 'hidden',
                boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
                transition: 'box-shadow 0.3s ease',
                cursor: 'crosshair',
                ...style,
            }}
            onMouseEnter={e => {
                e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,0,0,0.7)'
                e.currentTarget.style.zIndex = '20'
            }}
            onMouseLeave={e => {
                e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,0,0,0.5)'
                e.currentTarget.style.zIndex = style.zIndex ?? ''
            }}
        >
            <ArtComp />
        </div>
    )
}

export default function ArtworkPanel() {
    const CARD_W = 140
    const CARD_H = Math.round(CARD_W * 4 / 3)
    const GAP = 12
    const COLLAGE_W = CARD_W * 2 + GAP
    const COLLAGE_H = CARD_H * 3 + GAP * 2

    return (
        <div style={{
            position: 'sticky',
            top: 80,
            height: 'calc(100vh - 80px)',
            width: '100%',
            minWidth: 380,
            background: 'var(--ink)',   // ← FIXED: was '#1a2410', now matches left side
            // borderLeft removed — no visible seam between columns
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            overflow: 'hidden',
            boxSizing: 'border-box',
        }}>
            <div style={{
                position: 'relative',
                width: COLLAGE_W,
                height: COLLAGE_H,
                flexShrink: 0,
            }}>
                <ArtCard ArtComp={ARTS[0]} style={{ width: CARD_W, height: CARD_H, top: 0, left: 0, zIndex: 1 }} />
                <ArtCard ArtComp={ARTS[1]} style={{ width: CARD_W, height: CARD_H, top: 0, right: 0, zIndex: 1 }} />
                <ArtCard ArtComp={ARTS[2]} style={{ width: CARD_W, height: CARD_H, top: CARD_H + GAP, left: '50%', transform: 'translateX(-50%)', zIndex: 2 }} />
                <ArtCard ArtComp={ARTS[3]} style={{ width: CARD_W, height: CARD_H, bottom: 0, left: 0, zIndex: 1 }} />
                <ArtCard ArtComp={ARTS[4]} style={{ width: CARD_W, height: CARD_H, bottom: 0, right: 0, zIndex: 1 }} />
            </div>
        </div>
    )
}
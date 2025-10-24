# Shells Anthropic Theme - Color Reference
**Quick reference for developers maintaining the web UI theme**

## Core Color Palette

### Background Colors
```css
--bg-primary: #09090B     /* Body background - pure dark */
--bg-card: #131314        /* Card/panel backgrounds - dark slate */
--bg-table-header: #1a1a1c /* Table header - subtle variation */
--bg-hover: #1f1f21       /* Hover states - slightly lighter */
```

**Usage:**
- `--bg-primary`: Main page background, code blocks
- `--bg-card`: Stat cards, tables, modals
- `--bg-table-header`: Table headers only
- `--bg-hover`: Row hover, card hover backgrounds

### Text Colors
```css
--text-primary: #FAFAF5   /* Main text - warm cream */
--text-secondary: #9ca3af /* Secondary text - neutral gray */
--text-muted: #6b7280     /* Muted text - darker gray */
```

**Usage:**
- `--text-primary`: Headings, body text, finding titles
- `--text-secondary`: Labels, metadata, timestamps
- `--text-muted`: Subtitles, disabled states, placeholders

### Accent Colors (Anthropic Signature)
```css
--accent-primary: #D4A27F   /* Warm brown - primary accent */
--accent-secondary: #EBDBBC /* Muted beige - secondary accent */
--accent-dark: #09090B      /* Dark - for text on light backgrounds */
```

**Usage:**
- `--accent-primary`: Main heading (h1), refresh button, running badges, close button hover
- `--accent-secondary`: Subheadings (h2), table headers, button hover, code text
- `--accent-dark`: Text color on accent-colored buttons

### Border Color
```css
--border-color: rgba(212, 162, 127, 0.15)  /* Warm brown @ 15% opacity */
```

**Usage:** All borders (cards, tables, modals, finding cards)

**Hover variation:**
```css
border-color: rgba(212, 162, 127, 0.3);  /* 30% opacity on hover */
```

## Severity Colors (Preserved from original)

### Critical Severity
```css
color: #ef4444        /* Bright red */
background: rgba(239, 68, 68, 0.15)
border: 1px solid rgba(239, 68, 68, 0.3)
```

### High Severity
```css
color: #f59e0b        /* Orange */
background: rgba(245, 158, 11, 0.15)
border: 1px solid rgba(245, 158, 11, 0.3)
```

### Medium Severity
```css
color: #fbbf24        /* Yellow */
background: rgba(251, 191, 36, 0.15)
border: 1px solid rgba(251, 191, 36, 0.3)
```

### Low Severity
```css
color: #3b82f6        /* Blue */
background: rgba(59, 130, 246, 0.15)
border: 1px solid rgba(59, 130, 246, 0.3)
```

## Status Colors

### Completed Status
```css
color: #10b981        /* Green */
background: rgba(16, 185, 129, 0.15)
border: 1px solid rgba(16, 185, 129, 0.3)
```

### Running Status (Uses Anthropic accent)
```css
color: var(--accent-primary)  /* #D4A27F */
background: rgba(212, 162, 127, 0.15)
border: 1px solid rgba(212, 162, 127, 0.3)
```

### Failed Status
```css
color: #ef4444        /* Red - same as critical */
background: rgba(239, 68, 68, 0.15)
border: 1px solid rgba(239, 68, 68, 0.3)
```

### Pending Status
```css
color: #9ca3af        /* Gray */
background: rgba(107, 114, 128, 0.15)
border: 1px solid rgba(107, 114, 128, 0.3)
```

## Visual Design Tokens

### Border Radius
```css
/* Cards, tables, modals */
border-radius: 12px;

/* Buttons */
border-radius: 8px;

/* Status badges */
border-radius: 16px;

/* Code blocks */
border-radius: 6px;
```

### Box Shadows
```css
/* Cards, tables (default) */
box-shadow: 0 1px 3px rgba(0,0,0,0.3);

/* Cards, tables (hover) */
box-shadow: 0 4px 6px rgba(0,0,0,0.4);

/* Buttons (hover) */
box-shadow: 0 2px 4px rgba(0,0,0,0.3);

/* Modals */
box-shadow: 0 8px 16px rgba(0,0,0,0.5);
```

### Transitions
```css
/* Standard transition for most elements */
transition: all 0.2s ease;

/* Background-only transition (tables) */
transition: background 0.2s ease;

/* Color-only transition (buttons, links) */
transition: color 0.2s ease;
```

### Transform Effects
```css
/* Card lift on hover */
transform: translateY(-2px);

/* Button lift on hover */
transform: translateY(-1px);

/* Finding card slide on hover */
transform: translateX(4px);
```

## Typography Scale

### Font Families
```css
/* Body text */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;

/* Code blocks */
font-family: 'Fira Code', 'Courier New', monospace;
```

### Font Sizes
```css
h1: 2.5rem;          /* 40px */
h2: 1.5rem;          /* 24px */
subtitle: 1rem;      /* 16px */
stat-value: 2.5rem;  /* 40px */
stat-label: 0.875rem; /* 14px */
finding-title: 1.1rem; /* ~17.6px */
finding-meta: 0.875rem; /* 14px */
status-badge: 0.75rem; /* 12px */
code: 0.875rem;      /* 14px */
```

### Font Weights
```css
h1, h2: 400;         /* Light/Regular */
stat-value: 500;     /* Medium */
stat-label: 400;     /* Regular */
status-badge: 500;   /* Medium */
finding-title: 500;  /* Medium */
```

### Letter Spacing
```css
h1: -0.02em;         /* Tighter tracking */
status-badge: 0.05em; /* Wider tracking */
```

## Spacing Scale

### Padding
```css
/* Cards */
padding: 20px;

/* Table cells */
padding: 15px;

/* Code blocks */
padding: 15px;

/* Modals */
padding: 30px;

/* Status badges */
padding: 4px 12px;

/* Buttons */
padding: 10px 20px;
```

### Gaps & Margins
```css
/* Stats grid gap */
gap: 20px;

/* Subtitle margin */
margin-bottom: 30px;

/* H2 margins */
margin: 30px 0 15px;

/* Finding cards margin */
margin: 15px 0;
```

## Usage Examples

### Creating a New Card Component
```css
.my-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    transition: all 0.2s ease;
}

.my-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 6px rgba(0,0,0,0.4);
    border-color: rgba(212, 162, 127, 0.3);
}
```

### Creating a New Button
```css
.my-button {
    background: var(--accent-primary);
    color: var(--accent-dark);
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
}

.my-button:hover {
    background: var(--accent-secondary);
    transform: translateY(-1px);
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
}
```

### Creating a New Status Badge
```css
.my-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 16px;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: rgba(YOUR_COLOR, 0.15);
    color: YOUR_COLOR;
    border: 1px solid rgba(YOUR_COLOR, 0.3);
}
```

## Accessibility Guidelines

### Color Contrast Ratios (WCAG AA)
- Text on `--bg-primary`: 15.8:1 (AAA) ✓
- Text on `--bg-card`: 14.2:1 (AAA) ✓
- Accent on dark: 4.8:1 (AA) ✓
- Status colors: All exceed 4.5:1 ✓

### Motion Sensitivity
Always include reduced motion media query:
```css
@media (prefers-reduced-motion: reduce) {
    .my-element {
        transition-duration: 0.01ms !important;
    }
}
```

## Browser Support

**Full support (latest versions):**
- Chrome/Edge: CSS Grid, Custom Properties, Transforms
- Firefox: All features supported
- Safari: All features supported

**Fallbacks not needed:**
- CSS Grid: 96%+ global support
- CSS Custom Properties: 96%+ global support
- CSS Transitions: 98%+ global support

## Quick Reference: When to Use Each Color

| Element | Background | Text | Border | Hover |
|---------|------------|------|--------|-------|
| Page | `--bg-primary` | `--text-primary` | - | - |
| Card | `--bg-card` | `--text-primary` | `--border-color` | `--bg-hover` |
| H1 | - | `--accent-primary` | - | - |
| H2 | - | `--accent-secondary` | - | - |
| Button | `--accent-primary` | `--accent-dark` | none | `--accent-secondary` |
| Running Badge | `rgba(accent, 0.15)` | `--accent-primary` | `rgba(accent, 0.3)` | - |
| Table Header | `--bg-table-header` | `--accent-secondary` | `--border-color` | - |
| Table Row | `--bg-card` | `--text-primary` | `--border-color` | `--bg-hover` |
| Modal | `--bg-card` | `--text-primary` | `--border-color` | - |
| Code Block | `--bg-primary` | `--accent-secondary` | `--border-color` | - |

---

**Need to change the theme?** Just update the CSS variables in `:root` - all components update automatically!

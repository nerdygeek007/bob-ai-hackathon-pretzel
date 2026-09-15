# Setup Guide

## Prerequisites

Before you begin, ensure you have the following installed:

- Node.js (v18 or later, Node 20 recommended)
- npm (v9 or later)
- Modern web browser (Chrome, Edge, Safari, Firefox)

## Quick Start (One-Click)

On Windows, simply run the launcher script in the root directory:

```cmd
run.bat
```

This will start the local Vite development server and launch Sentinel-X at `http://localhost:5173`.

## Manual Installation & Local Run

```bash
# 1. Clone the repository
git clone https://github.com/nerdygeek007/bob-ai-hackathon-pretzel.git
cd bob-ai-hackathon-pretzel/src

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

The application will be available at: `http://localhost:5173`

## Production Build & Netlify Packaging

To generate an optimized production build:

```bash
cd src
npm run build
```

To build and package the ready-to-deploy Netlify archive:

```cmd
package-netlify.bat
```

This creates `sentinel-x-ui-netlify.zip` in the root directory, which can be dragged and dropped directly onto [https://app.netlify.com/drop](https://app.netlify.com/drop).

## Live Demo Access

A live version of the application is continuously hosted at:
**[https://stately-pudding-ce9c61.netlify.app](https://stately-pudding-ce9c61.netlify.app)**

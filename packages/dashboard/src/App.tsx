import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { SpeedInsights } from '@vercel/speed-insights/react'
import Executive from './views/Executive'
import ScanDetail from './views/ScanDetail'
import Scans from './views/Scans'
import Compliance from './views/Compliance'
import './index.css'

const basename = import.meta.env.BASE_URL.replace(/\/$/, '') || undefined

function App() {
  return (
    <BrowserRouter basename={basename}>
      <div className="app">
        <nav className="nav">
          <span className="nav-brand">NullVoid</span>
          <div className="nav-links">
            <NavLink to="/" end className={({ isActive }) => (isActive ? 'active' : '')}>
              Executive
            </NavLink>
            <NavLink to="/scans" className={({ isActive }) => (isActive ? 'active' : '')}>
              Scans
            </NavLink>
            <NavLink to="/compliance" className={({ isActive }) => (isActive ? 'active' : '')}>
              Compliance
            </NavLink>
          </div>
        </nav>
        <main className="main">
          <Routes>
            <Route path="/" element={<Executive />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/compliance" element={<Compliance />} />
          </Routes>
        </main>
        <SpeedInsights />
      </div>
    </BrowserRouter>
  )
}

export default App

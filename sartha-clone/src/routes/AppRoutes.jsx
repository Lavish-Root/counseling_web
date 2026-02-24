import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Home from '../pages/Home';
import About from '../pages/About';
import Counselling from '../pages/Counselling';
import Courses from '../pages/Courses';
import Connector from '../pages/Connector';
import EBooks from '../pages/EBooks';
import Terms from '../pages/Terms';
import Privacy from '../pages/Privacy';
import Refund from '../pages/Refund';
import Blogs from '../pages/Blogs';
import PredictorNEETUG from '../pages/PredictorNEETUG'; // Import PredictorNEETUG
import PreferenceList from '../pages/PreferenceList';
import AdminDashboard from '../pages/AdminDashboard'; // Import AdminDashboard
import Login from '../pages/Login'; // Import Login
import Register from '../pages/Register'; // Import Register
import ForgotPassword from '../pages/ForgotPassword'; // Import ForgotPassword
import MBBSCounselling from '../pages/MBBSCounselling'; // Import MBBSCounselling
import BDSCounselling from '../pages/BDSCounselling'; // Import BDSCounselling
import AyushCounselling from '../pages/AyushCounselling'; // Import AyushCounselling
import BVScCounselling from '../pages/BVScCounselling'; // Import BVScCounselling
import CUETCounselling from '../pages/CUETCounselling'; // Import CUETCounselling
import JEECounselling from '../pages/JEECounselling'; // Import JEECounselling
import CentralGovtCounselling from '../pages/CentralGovtCounselling'; // Import CentralGovtCounselling
import StateGovtCounselling from '../pages/StateGovtCounselling'; // Import StateGovtCounselling

import Cart from '../pages/Cart'; // Import Cart








const AppRoutes = () => {
    return (
        <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/about-us" element={<About />} />
            <Route path="/counselling" element={<Counselling />} />
            <Route path="/counselling/mbbs" element={<MBBSCounselling />} />
            <Route path="/counselling/bds" element={<BDSCounselling />} />
            <Route path="/counselling/ayush" element={<AyushCounselling />} />
            <Route path="/counselling/bvsc-ah" element={<BVScCounselling />} />
            <Route path="/counselling/cuet" element={<CUETCounselling />} />
            <Route path="/counselling/jee" element={<JEECounselling />} />
            <Route path="/counselling/central-govt" element={<CentralGovtCounselling />} />
            <Route path="/counselling/state-govt" element={<StateGovtCounselling />} />
            <Route path="/ebooks" element={<EBooks />} />
            <Route path="/counselling/:type" element={<Counselling />} /> {/* Placeholder for other sub-routes */}
            <Route path="/cart" element={<Cart />} />
            <Route path="/courses" element={<Courses />} />
            <Route path="/connector" element={<Connector />} />
            <Route path="/predictor-neet-ug" element={<PredictorNEETUG />} />

            <Route path="/blogs" element={<Blogs />} />
            <Route path="/neet-pg-preference-list" element={<PreferenceList />} />
            <Route path="/terms" element={<Terms />} />
            <Route path="/privacy" element={<Privacy />} />
            <Route path="/refund" element={<Refund />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/forgot-password" element={<ForgotPassword />} /> {/* Forgot Password Route */}
            <Route path="/admin" element={<AdminDashboard />} /> {/* Admin Dashboard Route */}
        </Routes>
    );
};

export default AppRoutes;

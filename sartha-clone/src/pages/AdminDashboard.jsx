import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const AdminDashboard = () => {
    const [users, setUsers] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');

    // Modal States
    const [showAddModal, setShowAddModal] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);

    // New User Form States
    const [newName, setNewName] = useState('');
    const [newEmail, setNewEmail] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [newRole, setNewRole] = useState('user');
    const [newPlan, setNewPlan] = useState('free');
    const [newStatus, setNewStatus] = useState('unpaid');
    const [isSubmitting, setIsSubmitting] = useState(false);

    const navigate = useNavigate();

    useEffect(() => {
        const fetchUsers = async () => {
            const token = localStorage.getItem('token');
            const currentUser = JSON.parse(localStorage.getItem('user'));

            if (!token || !currentUser || currentUser.role !== 'admin') {
                navigate('/');
                return;
            }

            try {
                const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
                const response = await axios.get(`${backendUrl}/api/admin/users`, {
                    headers: {
                        'x-auth-token': token
                    }
                });
                setUsers(response.data);
            } catch (err) {
                console.error(err);
                setError('Failed to fetch user data. Please ensure you have administrative privileges.');
                if (err.response && (err.response.status === 401 || err.response.status === 403)) {
                    navigate('/');
                }
            } finally {
                setIsLoading(false);
            }
        };

        fetchUsers();
    }, [navigate]);

    const fetchUsersData = async () => {
        setIsLoading(true);
        try {
            const token = localStorage.getItem('token');
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            const response = await axios.get(`${backendUrl}/api/admin/users`, {
                headers: { 'x-auth-token': token }
            });
            setUsers(response.data);
        } catch (err) {
            console.error(err);
        } finally {
            setIsLoading(false);
        }
    };

    const handleAddUser = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            const token = localStorage.getItem('token');
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            await axios.post(`${backendUrl}/api/admin/users`, {
                name: newName,
                email: newEmail,
                password: newPassword,
                role: newRole,
                subscriptionPlan: newPlan,
                paymentStatus: newStatus
            }, {
                headers: { 'x-auth-token': token }
            });

            // Reset form and close modal
            setShowAddModal(false);
            setNewName(''); setNewEmail(''); setNewPassword('');
            setNewRole('user'); setNewPlan('free'); setNewStatus('unpaid');

            // Refresh list
            fetchUsersData();
            alert('User successfully added!');
        } catch (err) {
            console.error(err);
            alert(err.response?.data?.message || 'Failed to add user');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDeleteUser = async (id, e) => {
        e.stopPropagation(); // Prevent opening the details modal
        if (!window.confirm('Are you sure you want to permanently delete this user?')) return;

        try {
            const token = localStorage.getItem('token');
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            await axios.delete(`${backendUrl}/api/admin/users/${id}`, {
                headers: { 'x-auth-token': token }
            });

            // Remove from local state
            setUsers(users.filter(u => u._id !== id));
            // Also close details modal if the user was deleting from within it or it was open
            if (selectedUser && selectedUser._id === id) setShowDetailsModal(false);

        } catch (err) {
            console.error(err);
            alert(err.response?.data?.message || 'Failed to delete user');
        }
    };

    const openDetails = (user) => {
        setSelectedUser(user);
        setShowDetailsModal(true);
    };

    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-purple"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-100 font-sans">
            {/* Top Navigation Bar */}
            <nav className="bg-white shadow-sm border-b border-gray-200">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <span className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary-pink to-primary-purple">
                                NextStep Admin
                            </span>
                        </div>
                        <div className="flex items-center">
                            <button
                                onClick={() => navigate('/')}
                                className="ml-4 px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
                            >
                                Back to Site
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Main Content Area */}
            <main className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-gray-900">Dashboard Overview</h1>
                    <p className="mt-1 text-sm text-gray-500">Manage your clients and application data.</p>
                </div>

                {error && (
                    <div className="mb-6 bg-red-50 border-l-4 border-red-400 p-4 rounded-md">
                        <div className="flex">
                            <div className="ml-3">
                                <p className="text-sm text-red-700">{error}</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Stats Cards */}
                <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3 mb-8">
                    <div className="bg-white overflow-hidden shadow rounded-lg">
                        <div className="p-5">
                            <div className="flex items-center">
                                <div className="flex-shrink-0 bg-primary-pink/10 rounded-md p-3">
                                    <svg className="h-6 w-6 text-primary-pink" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                                    </svg>
                                </div>
                                <div className="ml-5 w-0 flex-1">
                                    <dl>
                                        <dt className="text-sm font-medium text-gray-500 truncate">Total Registered Users</dt>
                                        <dd className="text-2xl font-semibold text-gray-900">{users.length}</dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="bg-white overflow-hidden shadow rounded-lg">
                        <div className="p-5">
                            <div className="flex items-center">
                                <div className="flex-shrink-0 bg-green-100 rounded-md p-3">
                                    <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <div className="ml-5 w-0 flex-1">
                                    <dl>
                                        <dt className="text-sm font-medium text-gray-500 truncate">Verified Accounts</dt>
                                        <dd className="text-2xl font-semibold text-gray-900">
                                            {users.filter(u => u.isVerified).length}
                                        </dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Users Table */}
                <div className="bg-white shadow rounded-lg relative">
                    <div className="px-4 py-5 sm:px-6 flex justify-between items-center border-b border-gray-200">
                        <h3 className="text-lg leading-6 font-medium text-gray-900">Recent Users</h3>
                        <button
                            onClick={() => setShowAddModal(true)}
                            className="bg-primary-purple text-white px-4 py-2 rounded-md hover:bg-[#6c4fb3] transition-colors text-sm font-medium shadow-sm"
                        >
                            + Add User
                        </button>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Joined</th>
                                    <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {users.map((user) => (
                                    <tr
                                        key={user._id}
                                        className="hover:bg-gray-50 transition-colors cursor-pointer"
                                        onClick={() => openDetails(user)}
                                    >
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="flex items-center">
                                                <div className="h-8 w-8 rounded-full bg-gradient-to-r from-primary-pink to-primary-purple flex items-center justify-center text-white font-bold text-sm">
                                                    {(user?.name && user.name.length > 0) ? user.name.charAt(0).toUpperCase() : 'U'}
                                                </div>
                                                <div className="ml-4">
                                                    <div className="text-sm font-medium text-gray-900">{user?.name || 'Unknown'}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="text-sm text-gray-500">{user?.email || 'No email'}</div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            {user.isVerified ? (
                                                <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Verified</span>
                                            ) : (
                                                <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">Unverified</span>
                                            )}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border-l border-gray-100">
                                            <span className={`px-2 py-1 rounded text-xs font-medium ${user?.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'}`}>
                                                {(user?.role || 'user').toUpperCase()}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                            {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <button
                                                onClick={(e) => handleDeleteUser(user._id, e)}
                                                className="text-red-600 hover:text-red-900 bg-red-50 hover:bg-red-100 px-3 py-1 rounded transition-colors"
                                            >
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {users.length === 0 && (
                                    <tr>
                                        <td colSpan="6" className="px-6 py-8 text-center text-gray-500 text-sm">
                                            No users found.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </main>

            {/* Add User Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-600 bg-opacity-75 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true" onClick={() => setShowAddModal(false)}>
                    <div
                        className="relative w-full max-w-lg bg-white rounded-lg text-left overflow-hidden shadow-2xl transform transition-all m-auto"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <form onSubmit={handleAddUser}>
                            <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                                <h3 className="text-lg leading-6 font-medium text-gray-900" id="modal-title">Add New User</h3>
                                <div className="mt-4 space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700">Name</label>
                                        <input type="text" required value={newName} onChange={e => setNewName(e.target.value)} className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm" />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700">Email</label>
                                        <input type="email" required value={newEmail} onChange={e => setNewEmail(e.target.value)} className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm" />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700">Password</label>
                                        <input type="password" required value={newPassword} onChange={e => setNewPassword(e.target.value)} className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm" />
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Role</label>
                                            <select value={newRole} onChange={e => setNewRole(e.target.value)} className="mt-1 block w-full bg-white border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm">
                                                <option value="user">User</option>
                                                <option value="admin">Admin</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Plan</label>
                                            <select value={newPlan} onChange={e => setNewPlan(e.target.value)} className="mt-1 block w-full bg-white border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm">
                                                <option value="free">Free</option>
                                                <option value="basic">Basic</option>
                                                <option value="premium">Premium</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Payment Status</label>
                                            <select value={newStatus} onChange={e => setNewStatus(e.target.value)} className="mt-1 block w-full bg-white border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-purple focus:border-primary-purple sm:text-sm">
                                                <option value="unpaid">Unpaid</option>
                                                <option value="paid">Paid</option>
                                                <option value="failed">Failed</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse border-t border-gray-200">
                                <button type="submit" disabled={isSubmitting} className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-purple text-base font-medium text-white hover:bg-[#6c4fb3] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50">
                                    {isSubmitting ? 'Saving...' : 'Add User'}
                                </button>
                                <button type="button" onClick={() => setShowAddModal(false)} className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* View Details Modal */}
            {showDetailsModal && selectedUser && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-600 bg-opacity-75 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true" onClick={() => setShowDetailsModal(false)}>
                    <div
                        className="relative w-full max-w-lg bg-white rounded-lg text-left overflow-hidden shadow-2xl transform transition-all m-auto"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                            <div className="flex justify-between items-start border-b border-gray-200 pb-4 mb-4">
                                <div className="flex items-center">
                                    <div className="h-12 w-12 rounded-full bg-gradient-to-r from-primary-pink to-primary-purple flex items-center justify-center text-white font-bold text-xl mr-4 shadow-sm">
                                        {(selectedUser?.name && selectedUser.name.length > 0) ? selectedUser.name.charAt(0).toUpperCase() : 'U'}
                                    </div>
                                    <div>
                                        <h3 className="text-xl leading-6 font-bold text-gray-900" id="modal-title">{selectedUser?.name || 'Unknown'}</h3>
                                        <p className="text-sm text-gray-500">{selectedUser?.email || 'No email'}</p>
                                    </div>
                                </div>
                                <span className={`px-2 py-1 rounded text-xs font-bold uppercase tracking-wider ${selectedUser?.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'}`}>
                                    {selectedUser?.role || 'user'}
                                </span>
                            </div>

                            <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                                <div className="sm:col-span-1">
                                    <dt className="text-sm font-medium text-gray-500">Subscription Plan</dt>
                                    <dd className="mt-1 text-sm text-gray-900 capitalize font-semibold">{selectedUser?.subscriptionPlan || 'Free'}</dd>
                                </div>
                                <div className="sm:col-span-1 border-l border-gray-100 pl-4">
                                    <dt className="text-sm font-medium text-gray-500">Payment Status</dt>
                                    <dd className="mt-1 text-sm text-gray-900">
                                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full capitalize ${selectedUser?.paymentStatus === 'paid' ? 'bg-green-100 text-green-800' :
                                            selectedUser?.paymentStatus === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                                            }`}>
                                            {selectedUser?.paymentStatus || 'Unpaid'}
                                        </span>
                                    </dd>
                                </div>
                                <div className="sm:col-span-1">
                                    <dt className="text-sm font-medium text-gray-500">Account Verified</dt>
                                    <dd className="mt-1 text-sm text-gray-900">{selectedUser?.isVerified ? 'Yes (OTP Completed)' : 'No (Pending OTP)'}</dd>
                                </div>
                                <div className="sm:col-span-1 border-l border-gray-100 pl-4">
                                    <dt className="text-sm font-medium text-gray-500">Join Date</dt>
                                    <dd className="mt-1 text-sm text-gray-900">{selectedUser?.createdAt ? new Date(selectedUser.createdAt).toLocaleString() : 'N/A'}</dd>
                                </div>
                            </dl>
                        </div>
                        <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex flex-row flex justify-between items-center border-t border-gray-200">
                            <button
                                type="button"
                                onClick={(e) => handleDeleteUser(selectedUser._id, e)}
                                className="inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:text-sm"
                            >
                                Delete Account
                            </button>
                            <button
                                type="button"
                                onClick={() => setShowDetailsModal(false)}
                                className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                            >
                                Close Settings
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AdminDashboard;

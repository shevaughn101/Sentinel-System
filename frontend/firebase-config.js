import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-app.js";
import { getAuth, GoogleAuthProvider, FacebookAuthProvider, OAuthProvider, signInWithPopup, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-auth.js";
import { getStorage, ref, uploadBytesResumable, getDownloadURL } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyDIQH8Asek3JHfBpK3gKzPCB4EsuQgxWm4",
  authDomain: "incidentplatform.firebaseapp.com",
  projectId: "incidentplatform",
  storageBucket: "incidentplatform.firebasestorage.app",
  messagingSenderId: "293328046929",
  appId: "1:293328046929:web:68f24f275bbb9e9728a170",
  measurementId: "G-E8PCB7HN9L"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const storage = getStorage(app);

const googleProvider = new GoogleAuthProvider();
const facebookProvider = new FacebookAuthProvider();
const appleProvider = new OAuthProvider('apple.com');

// Helper to get token
async function getAuthToken() {
    const user = auth.currentUser;
    if (user) {
        return await user.getIdToken();
    }
    return null;
}

// Fetch helper with auth
async function apiFetch(url, options = {}) {
    const token = await getAuthToken();
    if (!token) {
        throw new Error("No user authenticated");
    }
    const headers = {
        'Authorization': `Bearer ${token}`,
        ...options.headers
    };
    if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    }
    return fetch(url, { ...options, headers });
}

export { 
    auth, 
    storage, 
    googleProvider, 
    facebookProvider, 
    appleProvider, 
    signInWithPopup, 
    signInWithEmailAndPassword, 
    createUserWithEmailAndPassword,
    onAuthStateChanged,
    signOut,
    ref,
    uploadBytesResumable,
    getDownloadURL,
    apiFetch,
    getAuthToken
};

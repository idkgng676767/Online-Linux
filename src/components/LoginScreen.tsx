// ============================================================
// LoginScreen — Real auth (login/register) via backend API
// ============================================================

import { useState, useCallback, memo } from 'react';
import { Moon, Power, User, LogIn, UserPlus } from 'lucide-react';
import { useOS } from '@/hooks/useOSStore';

const API_BASE = 'http://localhost:5001/api/auth';

const LoginScreen = memo(function LoginScreen() {
  const { dispatch } = useOS();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = useCallback(async () => {
    if (!username.trim() || !password) {
      setError('Please fill in all fields');
      return;
    }
    setIsLoading(true);
    setError('');
    try {
      const endpoint = mode === 'login' ? `${API_BASE}/login` : `${API_BASE}/register`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || data.error || `${mode === 'login' ? 'Login' : 'Registration'} failed`);
        return;
      }
      dispatch({ type: 'LOGIN', username: data.username, token: data.token });
    } catch (err) {
      setError('Could not connect to server');
    } finally {
      setIsLoading(false);
    }
  }, [mode, username, password, dispatch]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') handleSubmit();
    },
    [handleSubmit]
  );

  const switchMode = useCallback(() => {
    setMode((m) => (m === 'login' ? 'register' : 'login'));
    setError('');
  }, []);

  return (
    <div
      className="fixed inset-0 z-[9998] flex items-center justify-center"
      style={{
        backgroundImage: 'url(/wallpaper-default.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
      }}
    >
      {/* Blur overlay */}
      <div
        className="absolute inset-0"
        style={{
          backdropFilter: 'blur(24px)',
          WebkitBackdropFilter: 'blur(24px)',
          background: 'rgba(0,0,0,0.4)',
        }}
      />

      {/* Login card */}
      <div
        className="relative z-10 w-[360px] rounded-[20px] p-10 flex flex-col items-center"
        style={{
          background: 'rgba(45,45,45,0.85)',
          boxShadow: '0 16px 48px rgba(0,0,0,0.6)',
          animation: 'loginEnter 400ms cubic-bezier(0.34, 1.56, 0.64, 1)',
        }}
      >
        {/* Avatar */}
        <div
          className="w-20 h-20 rounded-full flex items-center justify-center border-[3px] border-[#7C4DFF] mb-4"
          style={{ background: 'linear-gradient(135deg, #7C4DFF, #4A148C)' }}
        >
          <User size={36} className="text-white" />
        </div>

        {/* Mode title */}
        <h2 className="text-xl font-semibold text-[#E0E0E0]">
          {mode === 'login' ? 'Sign In' : 'Create Account'}
        </h2>

        {/* Username input */}
        <div className="w-full mt-6 relative">
          <input
            type="text"
            value={username}
            onChange={(e) => { setUsername(e.target.value); setError(''); }}
            onKeyDown={handleKeyDown}
            placeholder="Username"
            autoComplete="username"
            className="w-full h-11 rounded-full px-5 text-sm text-[#E0E0E0] outline-none transition-all"
            style={{
              background: '#1A1A1A',
              border: `1px solid ${error ? '#F44336' : 'rgba(255,255,255,0.1)'}`,
            }}
            onFocus={(e) => {
              if (!error) e.currentTarget.style.borderColor = '#7C4DFF';
              e.currentTarget.style.boxShadow = '0 0 0 3px rgba(124,77,255,0.15)';
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = error ? '#F44336' : 'rgba(255,255,255,0.1)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          />
        </div>

        {/* Password input */}
        <div className="w-full mt-3 relative">
          <input
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); setError(''); }}
            onKeyDown={handleKeyDown}
            placeholder="Password"
            autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            className="w-full h-11 rounded-full px-5 text-sm text-[#E0E0E0] outline-none transition-all"
            style={{
              background: '#1A1A1A',
              border: `1px solid ${error ? '#F44336' : 'rgba(255,255,255,0.1)'}`,
            }}
            onFocus={(e) => {
              if (!error) e.currentTarget.style.borderColor = '#7C4DFF';
              e.currentTarget.style.boxShadow = '0 0 0 3px rgba(124,77,255,0.15)';
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = error ? '#F44336' : 'rgba(255,255,255,0.1)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          />
        </div>

        {/* Error message */}
        {error && (
          <p className="mt-2 text-xs text-[#F44336] text-center w-full">{error}</p>
        )}

        {/* Submit button */}
        <button
          onClick={handleSubmit}
          disabled={isLoading}
          className="w-full h-11 rounded-full mt-4 text-sm font-semibold text-white transition-colors flex items-center justify-center gap-2"
          style={{
            background: isLoading ? '#673AB7' : '#7C4DFF',
            transform: 'scale(1)',
            transition: 'all 150ms ease',
          }}
          onMouseEnter={(e) => { if (!isLoading) e.currentTarget.style.background = '#9575FF'; }}
          onMouseLeave={(e) => { if (!isLoading) e.currentTarget.style.background = '#7C4DFF'; }}
          onMouseDown={(e) => { e.currentTarget.style.transform = 'scale(0.97)'; }}
          onMouseUp={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
        >
          {isLoading ? (
            <>
              <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
              <span>{mode === 'login' ? 'Signing in...' : 'Creating account...'}</span>
            </>
          ) : (
            <>
              {mode === 'login' ? <LogIn size={16} /> : <UserPlus size={16} />}
              {mode === 'login' ? 'Sign In' : 'Create Account'}
            </>
          )}
        </button>

        {/* Toggle login / register */}
        <button
          onClick={switchMode}
          className="mt-3 text-sm text-[#7C4DFF] hover:text-[#9575FF] transition-colors"
        >
          {mode === 'login' ? "Don't have an account? Register" : 'Already have an account? Sign In'}
        </button>

        {/* Power options */}
        <div className="flex items-center gap-4 mt-6 pt-4 w-full justify-center"
          style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
        >
          <button className="w-8 h-8 rounded-lg flex items-center justify-center text-[#9E9E9E] hover:text-[#E0E0E0] hover:bg-white/[0.06] transition-all">
            <Power size={16} />
          </button>
          <button className="w-8 h-8 rounded-lg flex items-center justify-center text-[#9E9E9E] hover:text-[#E0E0E0] hover:bg-white/[0.06] transition-all">
            <Moon size={16} />
          </button>
        </div>
      </div>

      <style>{`
        @keyframes loginEnter {
          from { opacity: 0; transform: scale(0.9); }
          to { opacity: 1; transform: scale(1); }
        }
        @keyframes loginShake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-8px); }
          50% { transform: translateX(8px); }
          75% { transform: translateX(-8px); }
        }
      `}</style>
    </div>
  );
});

export default LoginScreen;

// Coarse user-agent description for display in the admin dashboard only.
// Never used as device identity or for authorization.
export function describeUserAgent(ua = '') {
  const s = String(ua);
  const browser = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /SamsungBrowser/.test(s) ? 'Samsung Internet'
    : /Firefox\//.test(s) ? 'Firefox' : /CriOS|Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : 'Unknown';
  const os = /Android/.test(s) ? 'Android' : /iPhone|iPad|iPod/.test(s) ? 'iOS' : /Windows/.test(s) ? 'Windows'
    : /Mac OS X|Macintosh/.test(s) ? 'macOS' : /CrOS/.test(s) ? 'ChromeOS' : /Linux/.test(s) ? 'Linux' : 'Unknown';
  const category = /iPad|Tablet/.test(s) ? 'Tablet' : /Mobi|iPhone|Android/.test(s) ? 'Mobile' : (s ? 'Desktop' : 'Unknown');
  return { browser, os, category };
}

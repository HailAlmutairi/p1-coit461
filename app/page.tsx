'use client';

import { useState } from 'react';

interface ScanResult {
  success: boolean;
  filename: string;
  file_hash: string;
  file_size: number;
  analysis_id: string;
  stats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
  };
  results: Record<string, any>;
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  total_scanners: number;
}

export default function VirusScannerPage() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const handleScan = async () => {
    if (!file) {
      setError('Please select a file first');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('https://backend-p1-coit461.onrender.com/scan', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Scan failed');
      }

      const data: ScanResult = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getThreatLevel = () => {
    if (!result) return null;
    if (result.malicious > 0) return 'danger';
    if (result.suspicious > 0) return 'warning';
    return 'safe';
  };

  const getThreatColor = () => {
    const level = getThreatLevel();
    if (level === 'danger') return 'text-red-600 bg-red-50 border-red-300';
    if (level === 'warning') return 'text-yellow-600 bg-yellow-50 border-yellow-300';
    return 'text-green-600 bg-green-50 border-green-300';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2">
            🛡️ VirusTotal File Scanner
          </h1>
          <p className="text-gray-600">
            Upload a file to scan for viruses and malware using VirusTotal
          </p>
        </div>

        {/* Upload Section */}
        <div className="bg-white rounded-lg shadow-lg p-8 mb-6">
          <div className="space-y-4">
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-indigo-400 transition">
              <input
                type="file"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
                accept="*/*"
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center"
              >
                <svg
                  className="w-16 h-16 text-gray-400 mb-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                  />
                </svg>
                <span className="text-lg text-gray-700 font-medium">
                  {file ? file.name : 'Click to select a file'}
                </span>
                <span className="text-sm text-gray-500 mt-2">
                  Maximum file size: 32MB
                </span>
              </label>
            </div>

            <button
              onClick={handleScan}
              disabled={!file || loading}
              className={`w-full py-3 px-6 rounded-lg font-semibold text-white transition ${
                !file || loading
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-indigo-600 hover:bg-indigo-700'
              }`}
            >
              {loading ? 'Scanning...' : 'Scan File'}
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 border border-red-300 text-red-700 px-4 py-3 rounded-lg mb-6">
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-indigo-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Analyzing file with VirusTotal...</p>
            <p className="text-sm text-gray-500 mt-2">This may take up to 30 seconds</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="bg-white rounded-lg shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-800 mb-6">Scan Results</h2>

            {/* Threat Level */}
            <div className={`border-2 rounded-lg p-6 mb-6 ${getThreatColor()}`}>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold mb-2">
                    {result.malicious > 0 && '⚠️ Threat Detected'}
                    {result.malicious === 0 && result.suspicious > 0 && '⚠️ Suspicious'}
                    {result.malicious === 0 && result.suspicious === 0 && '✅ Safe'}
                  </h3>
                  <p className="text-sm">
                    {result.malicious} / {result.total_scanners} security vendors flagged this file
                  </p>
                </div>
                <div className="text-4xl font-bold">
                  {result.malicious > 0 ? result.malicious : '0'}
                </div>
              </div>
            </div>

            {/* File Info */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-sm text-gray-600">Filename</p>
                <p className="font-semibold text-gray-800 truncate">{result.filename}</p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-sm text-gray-600">File Size</p>
                <p className="font-semibold text-gray-800">
                  {(result.file_size / 1024).toFixed(2)} KB
                </p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg col-span-2">
                <p className="text-sm text-gray-600">SHA-256</p>
                <p className="font-mono text-xs text-gray-800 break-all">{result.file_hash}</p>
              </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-4 gap-4 mb-6">
              <div className="text-center p-4 bg-red-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">{result.malicious}</div>
                <div className="text-sm text-gray-600">Malicious</div>
              </div>
              <div className="text-center p-4 bg-yellow-50 rounded-lg">
                <div className="text-2xl font-bold text-yellow-600">{result.suspicious}</div>
                <div className="text-sm text-gray-600">Suspicious</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-gray-600">{result.undetected}</div>
                <div className="text-sm text-gray-600">Undetected</div>
              </div>
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">{result.harmless}</div>
                <div className="text-sm text-gray-600">Harmless</div>
              </div>
            </div>

            {/* Detailed Results */}
            <div>
              <h3 className="text-lg font-bold text-gray-800 mb-4">
                Detailed Scanner Results
              </h3>
              <div className="max-h-96 overflow-y-auto border rounded-lg">
                <table className="w-full">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                        Vendor
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                        Result
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                        Detection
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {Object.entries(result.results).map(([vendor, data]: [string, any]) => (
                      <tr key={vendor} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm text-gray-800">{vendor}</td>
                        <td className="px-4 py-3 text-sm">
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              data.category === 'malicious'
                                ? 'bg-red-100 text-red-800'
                                : data.category === 'suspicious'
                                ? 'bg-yellow-100 text-yellow-800'
                                : data.category === 'undetected'
                                ? 'bg-gray-100 text-gray-800'
                                : 'bg-green-100 text-green-800'
                            }`}
                          >
                            {data.category}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {data.result || 'Clean'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
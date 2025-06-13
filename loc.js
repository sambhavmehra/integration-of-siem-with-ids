import React, { useState, useEffect } from 'react';
import { Search, MapPin, Shield, AlertTriangle, Globe, Server, Clock, Wifi, Eye, Database } from 'lucide-react';

const AdvancedIPGeolocationTool = () => {
  const [ipAddress, setIpAddress] = useState('');
  const [locationData, setLocationData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [analysisMode, setAnalysisMode] = useState('standard');

  // Simulate advanced IP geolocation analysis
  const analyzeIP = async (ip) => {
    setLoading(true);
    setError('');
    
    try {
      // Simulate API calls to multiple geolocation services
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Mock data - in real implementation, this would call actual APIs
      const mockData = generateMockLocationData(ip);
      setLocationData(mockData);
      
      // Add to history
      setHistory(prev => [
        { ip, timestamp: new Date().toISOString(), data: mockData },
        ...prev.slice(0, 9)
      ]);
      
    } catch (err) {
      setError('Failed to analyze IP address. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const generateMockLocationData = (ip) => {
    // Check if private IP
    const isPrivateIP = isPrivateIPAddress(ip);
    
    if (isPrivateIP) {
      return {
        ip,
        isPrivate: true,
        country: 'Private Network',
        city: 'Local Network',
        region: 'Private',
        latitude: 0,
        longitude: 0,
        isp: 'Private Network',
        organization: 'Local Network',
        timezone: 'Local',
        threatLevel: 'low',
        isVPN: false,
        isProxy: false,
        isTor: false,
        confidence: 100,
        realLocation: null
      };
    }

    // Generate realistic mock data based on IP
    const locations = [
      { country: 'United States', city: 'San Francisco', region: 'California', lat: 37.7749, lng: -122.4194, timezone: 'America/Los_Angeles' },
      { country: 'Germany', city: 'Frankfurt', region: 'Hessen', lat: 50.1109, lng: 8.6821, timezone: 'Europe/Berlin' },
      { country: 'Singapore', city: 'Singapore', region: 'Singapore', lat: 1.3521, lng: 103.8198, timezone: 'Asia/Singapore' },
      { country: 'United Kingdom', city: 'London', region: 'England', lat: 51.5074, lng: -0.1278, timezone: 'Europe/London' },
      { country: 'Japan', city: 'Tokyo', region: 'Tokyo', lat: 35.6762, lng: 139.6503, timezone: 'Asia/Tokyo' },
      { country: 'Canada', city: 'Toronto', region: 'Ontario', lat: 43.6532, lng: -79.3832, timezone: 'America/Toronto' },
    ];

    const isps = [
      'Google LLC', 'Amazon Technologies Inc.', 'Cloudflare, Inc.', 'Microsoft Corporation',
      'Digital Ocean LLC', 'Linode LLC', 'Vultr Holdings LLC', 'Hetzner Online GmbH'
    ];

    const vpnProviders = [
      'NordVPN', 'ExpressVPN', 'Surfshark', 'CyberGhost', 'Private Internet Access',
      'ProtonVPN', 'Mullvad VPN', 'WindScribe'
    ];

    const location = locations[Math.floor(Math.random() * locations.length)];
    const isp = isps[Math.floor(Math.random() * isps.length)];
    
    // Simulate VPN/Proxy detection
    const isVPN = Math.random() > 0.7;
    const isProxy = !isVPN && Math.random() > 0.8;
    const isTor = !isVPN && !isProxy && Math.random() > 0.95;
    
    let threatLevel = 'low';
    if (isTor) threatLevel = 'high';
    else if (isVPN || isProxy) threatLevel = 'medium';
    
    let realLocation = null;
    if (isVPN) {
      // Simulate real location detection for VPN
      const realLoc = locations[Math.floor(Math.random() * locations.length)];
      realLocation = {
        ...realLoc,
        detectionMethod: 'DNS leak analysis',
        confidence: Math.floor(Math.random() * 40) + 60 // 60-100%
      };
    }

    return {
      ip,
      isPrivate: false,
      country: location.country,
      city: location.city,
      region: location.region,
      latitude: location.lat,
      longitude: location.lng,
      isp: isVPN ? vpnProviders[Math.floor(Math.random() * vpnProviders.length)] : isp,
      organization: isVPN ? 'VPN Service Provider' : isp,
      timezone: location.timezone,
      threatLevel,
      isVPN,
      isProxy,
      isTor,
      confidence: Math.floor(Math.random() * 30) + 70, // 70-100%
      realLocation,
      // Additional advanced data
      asn: `AS${Math.floor(Math.random() * 65535)}`,
      hostnames: [`host${Math.floor(Math.random() * 999)}.${location.city.toLowerCase()}.example.com`],
      ports: generateOpenPorts(),
      lastSeen: new Date(Date.now() - Math.random() * 86400000 * 30).toISOString(),
      riskScore: Math.floor(Math.random() * 100),
      reputation: generateReputation()
    };
  };

  const generateOpenPorts = () => {
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
    const numPorts = Math.floor(Math.random() * 5) + 1;
    return commonPorts.sort(() => 0.5 - Math.random()).slice(0, numPorts);
  };

  const generateReputation = () => {
    const sources = ['VirusTotal', 'AbuseIPDB', 'Talos', 'Spamhaus', 'SURBL'];
    const reputation = {};
    sources.forEach(source => {
      reputation[source] = Math.random() > 0.8 ? 'malicious' : 'clean';
    });
    return reputation;
  };

  const isPrivateIPAddress = (ip) => {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^::1$/,
      /^fe80:/
    ];
    return privateRanges.some(range => range.test(ip));
  };

  const validateIP = (ip) => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  };

  const handleSearch = () => {
    if (!ipAddress.trim()) {
      setError('Please enter an IP address');
      return;
    }
    
    if (!validateIP(ipAddress.trim())) {
      setError('Please enter a valid IP address');
      return;
    }
    
    analyzeIP(ipAddress.trim());
  };

  const handleQuickSearch = (ip) => {
    setIpAddress(ip);
    analyzeIP(ip);
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'high': return 'text-red-600 bg-red-50 border-red-200';
      case 'medium': return 'text-orange-600 bg-orange-50 border-orange-200';
      default: return 'text-green-600 bg-green-50 border-green-200';
    }
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 90) return 'text-green-600';
    if (confidence >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4 flex items-center justify-center gap-3">
            <Globe className="text-blue-600" />
            Advanced IP Geolocation Tool
          </h1>
          <p className="text-gray-600 text-lg">
            Detect original IP locations, bypass VPN/Proxy masking, and analyze network intelligence
          </p>
        </div>

        {/* Search Section */}
        <div className="bg-white rounded-2xl shadow-xl p-8 mb-8">
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="flex-1">
              <input
                type="text"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                placeholder="Enter IP address (e.g., 8.8.8.8)"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg"
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              />
            </div>
            <button
              onClick={handleSearch}
              disabled={loading}
              className={`px-8 py-3 bg-blue-600 text-white rounded-lg font-semibold transition-all duration-200 flex items-center gap-2 ${
                loading ? 'opacity-50 cursor-not-allowed' : 'hover:bg-blue-700 hover:shadow-lg'
              }`}
            >
              {loading ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <Search size={20} />
                  Analyze IP
                </>
              )}
            </button>
          </div>

          {/* Analysis Mode Selector */}
          <div className="flex gap-4 mb-4">
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="analysisMode"
                value="standard"
                checked={analysisMode === 'standard'}
                onChange={(e) => setAnalysisMode(e.target.value)}
                className="text-blue-600"
              />
              <span>Standard Analysis</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="analysisMode"
                value="deep"
                checked={analysisMode === 'deep'}
                onChange={(e) => setAnalysisMode(e.target.value)}
                className="text-blue-600"
              />
              <span>Deep Analysis (VPN Detection)</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="analysisMode"
                value="threat"
                checked={analysisMode === 'threat'}
                onChange={(e) => setAnalysisMode(e.target.value)}
                className="text-blue-600"
              />
              <span>Threat Intelligence</span>
            </label>
          </div>

          {/* Quick Search Examples */}
          <div className="flex flex-wrap gap-2">
            <span className="text-gray-600 text-sm">Quick examples:</span>
            {['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9'].map(ip => (
              <button
                key={ip}
                onClick={() => handleQuickSearch(ip)}
                className="px-3 py-1 bg-gray-100 text-gray-700 rounded-md text-sm hover:bg-gray-200 transition-colors"
              >
                {ip}
              </button>
            ))}
          </div>

          {error && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <div className="flex items-center gap-2 text-red-600">
                <AlertTriangle size={20} />
                <span>{error}</span>
              </div>
            </div>
          )}
        </div>

        {/* Results Section */}
        {locationData && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            {/* Main Location Info */}
            <div className="lg:col-span-2 bg-white rounded-2xl shadow-xl p-8">
              <div className="flex items-center gap-3 mb-6">
                <MapPin className="text-blue-600" size={24} />
                <h2 className="text-2xl font-bold text-gray-900">Location Analysis</h2>
                <div className={`px-3 py-1 rounded-full text-sm font-medium border ${getThreatColor(locationData.threatLevel)}`}>
                  {locationData.threatLevel.toUpperCase()} RISK
                </div>
              </div>

              {locationData.isPrivate ? (
                <div className="text-center py-8">
                  <Server className="mx-auto mb-4 text-gray-400" size={48} />
                  <h3 className="text-xl font-semibold text-gray-700 mb-2">Private Network IP</h3>
                  <p className="text-gray-600">This IP address belongs to a private network and cannot be geolocated.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Primary Location */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">IP Address</label>
                        <p className="text-lg font-mono bg-gray-50 px-3 py-2 rounded">{locationData.ip}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">Country</label>
                        <p className="text-lg font-semibold">{locationData.country}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">City / Region</label>
                        <p className="text-lg">{locationData.city}, {locationData.region}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">Coordinates</label>
                        <p className="text-lg font-mono">{locationData.latitude}, {locationData.longitude}</p>
                      </div>
                    </div>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">ISP / Organization</label>
                        <p className="text-lg">{locationData.isp}</p>
                        <p className="text-sm text-gray-600">{locationData.organization}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">Timezone</label>
                        <p className="text-lg">{locationData.timezone}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">ASN</label>
                        <p className="text-lg font-mono">{locationData.asn}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-500 mb-1">Confidence</label>
                        <p className={`text-lg font-semibold ${getConfidenceColor(locationData.confidence)}`}>
                          {locationData.confidence}%
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* VPN/Proxy Detection */}
                  {(locationData.isVPN || locationData.isProxy || locationData.isTor) && (
                    <div className="border-t pt-6">
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Shield className="text-orange-600" />
                        Anonymization Detected
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {locationData.isVPN && (
                          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                            <div className="font-semibold text-orange-800">VPN Detected</div>
                            <div className="text-sm text-orange-600">Virtual Private Network</div>
                          </div>
                        )}
                        {locationData.isProxy && (
                          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                            <div className="font-semibold text-yellow-800">Proxy Detected</div>
                            <div className="text-sm text-yellow-600">HTTP/SOCKS Proxy</div>
                          </div>
                        )}
                        {locationData.isTor && (
                          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                            <div className="font-semibold text-red-800">Tor Network</div>
                            <div className="text-sm text-red-600">Anonymous Network</div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Real Location Detection */}
                  {locationData.realLocation && (
                    <div className="border-t pt-6">
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Eye className="text-green-600" />
                        Detected Real Location
                      </h3>
                      <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <div className="font-semibold text-green-800">
                              {locationData.realLocation.city}, {locationData.realLocation.country}
                            </div>
                            <div className="text-sm text-green-600">
                              Coordinates: {locationData.realLocation.lat}, {locationData.realLocation.lng}
                            </div>
                          </div>
                          <div>
                            <div className="text-sm text-green-600">
                              Detection Method: {locationData.realLocation.detectionMethod}
                            </div>
                            <div className="text-sm text-green-600">
                              Confidence: {locationData.realLocation.confidence}%
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Technical Details */}
            <div className="space-y-6">
              {/* Network Details */}
              <div className="bg-white rounded-2xl shadow-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Server className="text-blue-600" />
                  Network Details
                </h3>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-500">Open Ports</label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {locationData.ports?.map(port => (
                        <span key={port} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                          {port}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500">Risk Score</label>
                    <div className="mt-1">
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${
                            locationData.riskScore > 70 ? 'bg-red-500' : 
                            locationData.riskScore > 40 ? 'bg-yellow-500' : 'bg-green-500'
                          }`}
                          style={{width: `${locationData.riskScore}%`}}
                        />
                      </div>
                      <span className="text-sm text-gray-600">{locationData.riskScore}/100</span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500">Last Seen</label>
                    <p className="text-sm">{new Date(locationData.lastSeen).toLocaleString()}</p>
                  </div>
                </div>
              </div>

              {/* Reputation Check */}
              <div className="bg-white rounded-2xl shadow-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Database className="text-purple-600" />
                  Reputation Analysis
                </h3>
                <div className="space-y-2">
                  {Object.entries(locationData.reputation || {}).map(([source, status]) => (
                    <div key={source} className="flex justify-between items-center">
                      <span className="text-sm text-gray-600">{source}</span>
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        status === 'clean' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Timeline */}
              <div className="bg-white rounded-2xl shadow-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Clock className="text-indigo-600" />
                  Recent Queries
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {history.map((entry, index) => (
                    <div key={index} className="flex justify-between items-center text-sm border-b pb-2">
                      <span className="font-mono">{entry.ip}</span>
                      <div className="text-right">
                        <div className="text-gray-600">{entry.data.city}</div>
                        <div className="text-xs text-gray-400">
                          {new Date(entry.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}
                  {history.length === 0 && (
                    <p className="text-gray-500 text-sm">No recent queries</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Features Section */}
        <div className="bg-white rounded-2xl shadow-xl p-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 text-center">Advanced Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="text-center p-4">
              <Globe className="mx-auto mb-3 text-blue-600" size={32} />
              <h3 className="font-semibold mb-2">Real Location Detection</h3>
              <p className="text-sm text-gray-600">Bypass VPN/Proxy masking to find original location</p>
            </div>
            <div className="text-center p-4">
              <Shield className="mx-auto mb-3 text-green-600" size={32} />
              <h3 className="font-semibold mb-2">Anonymization Detection</h3>
              <p className="text-sm text-gray-600">Identify VPNs, proxies, and Tor networks</p>
            </div>
            <div className="text-center p-4">
              <Database className="mx-auto mb-3 text-purple-600" size={32} />
              <h3 className="font-semibold mb-2">Threat Intelligence</h3>
              <p className="text-sm text-gray-600">Cross-reference with multiple security databases</p>
            </div>
            <div className="text-center p-4">
              <Eye className="mx-auto mb-3 text-orange-600" size={32} />
              <h3 className="font-semibold mb-2">Deep Analysis</h3>
              <p className="text-sm text-gray-600">Advanced network fingerprinting and analysis</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdvancedIPGeolocationTool;
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage' || request.action === 'customScan') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0].id;
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: scanHeaders,
        args: [request.rule || null]
      }, (results) => {
        sendResponse(results[0].result);
      });
    });
    return true;  // 保持消息通道开放
  }
});

function scanHeaders(customRule) {
  const headers = {};
  const req = new XMLHttpRequest();
  req.open('HEAD', window.location.href, false);
  req.send();
  req.getAllResponseHeaders().split('\r\n').forEach(line => {
    const [key, value] = line.split(': ');
    if (key) headers[key.toLowerCase()] = value;
  });

  const report = {
    csp: headers['content-security-policy'] || 'Missing CSP - Potential XSS risk',
    hsts: headers['strict-transport-security'] || 'Missing HSTS - MITM vulnerability',
    xfo: headers['x-frame-options'] || 'Missing X-Frame-Options - Clickjacking risk'
  };
  if (customRule) {
    report.custom = headers[customRule.toLowerCase()] || `Missing ${customRule}`;
  }
  return report;
}
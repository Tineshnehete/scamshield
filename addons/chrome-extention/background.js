chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("Received message:", request);
  if (request.action === "fetchReport") {
    fetch(`http://localhost:8000/scanner/scan/`,
      {
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          method: "POST",
          body: JSON.stringify({ url: request.url })
      })
      .then(response => response.json())
      .then(data => {
        console.log("API Response:", data);
        sendResponse({ report: data });
      })
      .catch(error => {
        console.error("Fetch error:", error);
        sendResponse({ error: JSON.stringify(error) });
      });
    return true; // Keeps the message channel open for sendResponse
  }
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active) {
    fetch(`http://localhost:8000/scanner/scan/`,
      {
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          method: "POST",
      body: JSON.stringify({ url: tab.url })
      })
      .then(response => response.json())
      .then(data => {
        console.log("API Response:", data);
        if (data?.report.trust_score < 50) {
          chrome.action.openPopup()
          }
      })
      .catch(error => {
        console.error("Fetch error:", error);
      });
    return true; // Keeps the message channel open for sendResponse
  }
  
});
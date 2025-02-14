function getScoreColor(score) {
  const red = Math.max(0, 255 - (score * 2.55));
  const green = Math.min(255, score * 2.55);
  return `rgb(${red}, ${green}, 0)`;
}
function getScoreMessage(score) {
  if (score >= 80) return "This website is highly trustworthy.";
  if (score >= 50) return "This website has moderate trust.";
  return "This website is suspicious. Proceed with caution.";
}
document.addEventListener("DOMContentLoaded", function() {
  function fetchReport(url) {
    console.log("Fetching report for:", url);
    chrome.runtime.sendMessage({ action: "fetchReport", url }, function(response) {
      const resultDiv = document.getElementById("result");
      if (chrome.runtime.lastError) {
        console.error("Runtime error:", chrome.runtime.lastError.message);
        resultDiv.innerText = "Error: " + chrome.runtime.lastError.message;
      } else if (response && response.report) {
        const report = response.report?.report;
        resultDiv.innerHTML = `
          <h3 style="color:${getScoreColor(report?.trust_score)};font-size:2rem">Trust Score: ${report.trust_score}</h3>
          <p class="message">${getScoreMessage(report.trust_score)}</p>
          <hr style="margine-top:25px"/>
          <p><strong>URL:</strong> ${report.url}</p>
          <p><strong>Rank:</strong> ${report.rank}</p>
          <p><strong>Age:</strong> ${report.age}</p>
          <h4>content_detection:</h4>
          <pre>${JSON.stringify(report.content_detection, null, 2)}</pre>
          <h4>WHOIS Info:</h4>
          <pre>${JSON.stringify(report.whois, null, 2)}</pre>
          <h4>SSL Info:</h4>
          <pre>${JSON.stringify(report.ssl, null, 2)}</pre>
        `;
      } else {
        resultDiv.innerText = JSON.stringify(response, null, 2);
      }
    });
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "fetchReport" && message.url) {
      fetchReport(message.url);
    }
  });

  // Initial fetch on load
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs && tabs.length > 0) {
      fetchReport(tabs[0].url);
    }
  });
}); 
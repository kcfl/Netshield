chrome.runtime.onInstalled.addListener(() => {
  console.log("NetShield Browser Guard installed.");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "CHECK_PAGE") {
    sendResponse({
      status: "placeholder",
      reason: "Browser-side detection logic is not implemented yet."
    });
  }
});

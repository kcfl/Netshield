const scanButton = document.getElementById("scanButton");
const status = document.getElementById("status");

scanButton.addEventListener("click", () => {
  status.textContent = "Placeholder scan only. Heuristics will be added later.";
});

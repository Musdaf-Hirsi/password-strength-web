const checkButton = document.getElementById("checkBtn");
const passwordInput = document.getElementById("password");
const breachToggle = document.getElementById("breachToggle");
const statusEl = document.getElementById("status");
const meterFill = document.getElementById("meterFill");
const scoreLabel = document.getElementById("scoreLabel");
const feedbackList = document.getElementById("feedbackList");
const warningList = document.getElementById("warningList");
const commonPasswordEl = document.getElementById("commonPassword");
const breachedResultEl = document.getElementById("breachedResult");
const crackTimesEl = document.getElementById("crackTimes");

const scoreColors = ["#fb7185", "#f97316", "#facc15", "#38bdf8", "#34d399"];

function setStatus(message) {
  statusEl.textContent = message;
}

function clearList(listEl) {
  listEl.innerHTML = "";
}

function addListItem(listEl, text) {
  const item = document.createElement("li");
  item.textContent = text;
  listEl.appendChild(item);
}

function updateMeter(score) {
  const percent = Math.min(Math.max(score, 0), 4) * 25;
  meterFill.style.width = `${percent}%`;
  meterFill.style.background = scoreColors[score] || scoreColors[0];
}

async function checkPassword() {
  const password = passwordInput.value;
  if (!password) {
    setStatus("Enter a password to evaluate.");
    return;
  }

  setStatus("Checking password strength...");
  clearList(feedbackList);
  clearList(warningList);
  clearList(crackTimesEl);
  commonPasswordEl.textContent = "";
  breachedResultEl.textContent = "";

  try {
    const response = await fetch("/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        password,
        check_breached: breachToggle.checked,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      setStatus(data.error || "Unable to evaluate password.");
      return;
    }

    updateMeter(data.score);
    scoreLabel.textContent = `${data.label} (score ${data.score}/4)`;
    setStatus("Evaluation complete.");

    if (data.feedback.length === 0) {
      addListItem(feedbackList, "No specific improvement tips.");
    } else {
      data.feedback.forEach((item) => addListItem(feedbackList, item));
    }

    if (data.warnings.length === 0) {
      addListItem(warningList, "No major red flags found.");
    } else {
      data.warnings.forEach((item) => addListItem(warningList, item));
    }

    commonPasswordEl.textContent = data.commonPassword
      ? "Common password detected. Choose something less predictable."
      : "Not found in the common-password list.";

    if (breachToggle.checked) {
      if (data.breached === true) {
        breachedResultEl.textContent = "Found in breach corpus. Do not use.";
        breachedResultEl.className = "warning";
      } else if (data.breached === false) {
        breachedResultEl.textContent = "Not found in breach corpus.";
        breachedResultEl.className = "success";
      } else {
        breachedResultEl.textContent = "Breached check unavailable or disabled.";
        breachedResultEl.className = "";
      }
    }

    const crackTimes = data.crackTimeEstimates || {};
    Object.entries(crackTimes).forEach(([label, value]) => {
      addListItem(crackTimesEl, `${label.replaceAll("_", " ")}: ${value}`);
    });
  } catch (error) {
    setStatus("Network error while checking password.");
  }
}

checkButton.addEventListener("click", checkPassword);

// Dark/Light Toggle
let toggleModeBtn = document.getElementById("toggleMode");
if(toggleModeBtn){
    toggleModeBtn.addEventListener("click", ()=>{
        document.body.classList.toggle("dark");
        toggleModeBtn.innerText = document.body.classList.contains("dark") ? "☀️ Light Mode" : "🌙 Dark Mode";
    });
}

// SMS Prediction
let predictBtn = document.getElementById("predictBtn");
if(predictBtn){
    predictBtn.addEventListener("click", async () => {
        const smsText = document.getElementById("smsInput").value.trim();
        if(!smsText){ alert("Enter SMS"); return; }
        const resultLabel = document.getElementById("resultLabel");
        resultLabel.innerText = "Checking...";
        try {
            const res = await fetch("/predict_sms", {
                method:"POST",
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify({sms:smsText})
            });
            const data = await res.json();
            if(data.status==="success"){
                resultLabel.innerText = "Prediction: " + data.prediction;
                // Add to history cards
                const history = document.getElementById("historyCards");
                const card = document.createElement("div");
                card.className = "card " + (data.prediction.toLowerCase()==="spam"?"spam":"ham");
                card.innerHTML = `<strong>${data.prediction}</strong>: ${smsText}`;
                history.prepend(card);
            } else {
                resultLabel.innerText = "Error: " + data.message;
            }
        } catch(err){
            resultLabel.innerText = "Error: " + err.message;
        }
    });
}
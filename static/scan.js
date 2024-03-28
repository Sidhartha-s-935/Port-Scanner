document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('scan-form');
    const resultsContainer = document.getElementById('results-container');
    const scanResults = document.getElementById('scan-results');

    form.addEventListener('submit', function (event) {
        event.preventDefault();

        const formData = new FormData(form);

        fetch('/scan', {
            method: 'POST',
            body: formData,
        })
        .then(response => response.json())
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    function displayResults(results) {
        scanResults.textContent = ''; // Clear existing content

        results.forEach(result => {
            scanResults.textContent += `Results for ${result.target}:\n`;
            scanResults.textContent += `Open ports:\n`;

            result.open_ports.forEach(portInfo => {
                scanResults.textContent += `Port ${portInfo[0]} (${portInfo[1].name || 'Unknown'}) is open. Version: ${portInfo[1].version || 'Unknown'} (${portInfo[1].product || 'Unknown'})\n`;
            });

            scanResults.textContent += `Geolocation Information:\n`;
            scanResults.textContent += `${result.geolocation}\n\n`;
        });
    }
});

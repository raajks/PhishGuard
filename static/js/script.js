/**
 * Phishing URL Detector - Frontend JavaScript
 * Handles UI interactions and API communication
 */

// DOM Elements
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const errorMessage = document.getElementById('errorMessage');
const loadingSection = document.getElementById('loadingSection');
const resultSection = document.getElementById('resultSection');
const resultCard = document.getElementById('resultCard');
const toggleFeaturesBtn = document.getElementById('toggleFeaturesBtn');
const featuresDetails = document.getElementById('featuresDetails');
const checkAnotherBtn = document.getElementById('checkAnotherBtn');
const shareBtn = document.getElementById('shareBtn');

// State
let lastResult = null;

// Chart instances storage
let charts = {
    confidence: null,
    riskFactors: null,
    features: null,
    threat: null
};

/**
 * Initialize event listeners
 */
document.addEventListener('DOMContentLoaded', function() {
    checkBtn.addEventListener('click', handleCheckURL);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            handleCheckURL();
        }
    });
    toggleFeaturesBtn.addEventListener('click', toggleFeatures);
    checkAnotherBtn.addEventListener('click', resetForm);
    shareBtn.addEventListener('click', copyResult);
    urlInput.addEventListener('input', clearError);
    
    // Add event listeners for sample URL buttons
    const sampleUrlButtons = document.querySelectorAll('.sample-url-btn');
    sampleUrlButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            handleSampleURLClick(this);
        });
    });
});

/**
 * Handle URL checking
 */
async function handleCheckURL() {
    const url = urlInput.value.trim();
    
    // Clear previous errors
    clearError();
    
    // Validate input
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    
    if (url.length > 2048) {
        showError('URL is too long (max 2048 characters)');
        return;
    }
    
    // Show loading state
    showLoading();
    
    try {
        // Make API request
        const response = await fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Display results
            displayResults(data);
            lastResult = data;
        } else {
            showError(data.message || 'An error occurred while analyzing the URL');
            hideLoading();
        }
        
    } catch (error) {
        console.error('Network error details:', error);
        console.error('Error message:', error.message);
        console.error('Error type:', error.name);
        showError('Network error. Please try again. Check browser console for details.');
        hideLoading();
    }
}

/**
 * Handle sample URL button clicks
 * Auto-fills input and runs prediction with smooth animation
 */
function handleSampleURLClick(buttonElement) {
    const sampleUrl = buttonElement.getAttribute('data-url');
    const urlType = buttonElement.getAttribute('data-type');
    
    if (!sampleUrl) return;
    
    // Add visual feedback animation
    buttonElement.style.transform = 'scale(0.95)';
    setTimeout(() => {
        buttonElement.style.transform = '';
    }, 150);
    
    // Fill input with sample URL
    urlInput.value = sampleUrl;
    
    // Show a brief tooltip/notification
    showToastNotification(`📋 Sample ${urlType} URL loaded! Click "Check URL" to analyze.`);
    
    // Focus input for better UX
    urlInput.focus();
    
    // Optional: Auto-scroll to input
    urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/**
 * Show toast notification
 */
function showToastNotification(message) {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 2rem;
        left: 50%;
        transform: translateX(-50%);
        background: linear-gradient(135deg, #6366f1 0%, #ec4899 100%);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        font-weight: 600;
        font-size: 0.9rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        animation: slideUp 0.3s ease, slideDown 0.3s ease 2.7s;
        z-index: 1000;
    `;
    
    document.body.appendChild(toast);
    
    // Remove after animation completes
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

/**
 * Display results in the UI
 */
function displayResults(data) {
    hideLoading();
    resultSection.classList.remove('hidden');
    
    // Scroll to result
    setTimeout(() => {
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
    
    const isPhishing = data.prediction === 'Phishing';
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultMessage = document.getElementById('resultMessage');
    const confidenceValue = document.getElementById('confidenceValue');
    const progressFill = document.getElementById('progressFill');
    const analyzedUrl = document.getElementById('analyzedUrl');
    
    // Update result icon and styling
    if (isPhishing) {
        resultIcon.textContent = '⚠️';
        resultTitle.textContent = 'Phishing Detected';
        resultTitle.className = 'result-title phishing';
        resultMessage.textContent = 'This URL has characteristics commonly found in phishing attacks. Proceed with caution!';
    } else {
        resultIcon.textContent = '✅';
        resultTitle.textContent = 'URL Appears Safe';
        resultTitle.className = 'result-title safe';
        resultMessage.textContent = 'This URL appears to be legitimate based on our analysis.';
    }
    
    // Update confidence
    const confidence = data.confidence;
    confidenceValue.textContent = `${confidence}%`;
    progressFill.style.width = confidence + '%';
    
    // Update progress bar color
    if (confidence >= 70) {
        if (isPhishing) {
            progressFill.style.background = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
        } else {
            progressFill.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
        }
    }
    
    // Display analyzed URL
    analyzedUrl.textContent = data.url;
    
    // Display and animate the process roadmap
    displayProcessRoadmap(data);
    
    // Display risk analysis breakdown
    displayRiskAnalysis(data);
    
    // Display features (features section will open automatically)
    displayFeatures(data.features);
    
    // Display detailed scan results
    displayScanResults(data);
    
    // Display charts
    displayCharts(data);
    
    // Display Explainable AI explanations
    displayExplanations(data.explanation);
}

/**
 * Display risk analysis breakdown with suspicious and safe factors
 */
function displayRiskAnalysis(data) {
    const features = data.features;
    const confidence = data.confidence;
    const isPhishing = data.prediction === 'Phishing';
    
    const suspiciousFactors = [];
    const safeFactors = [];
    
    // Analyze each feature and categorize it
    
    // 1. @ Symbol (Highly suspicious if present)
    if (features.has_at_symbol === 1) {
        suspiciousFactors.push({
            name: '@ Symbol Found',
            detail: 'URLs with @ symbols are commonly used to hide real domain in phishing attacks'
        });
    } else {
        safeFactors.push({
            name: 'No @ Symbol',
            detail: 'Good indicator - legitimate URLs rarely have @ symbols'
        });
    }
    
    // 2. IP Address (Highly suspicious if present)
    if (features.has_ip_address === 1) {
        suspiciousFactors.push({
            name: 'IP Address Detected',
            detail: 'URLs using IP addresses instead of domain names are often phishing'
        });
    } else {
        safeFactors.push({
            name: 'Uses Domain Name',
            detail: 'Good practice - legitimate sites use proper domain names'
        });
    }
    
    // 3. Suspicious Keywords
    if (features.has_suspicious_keywords === 1) {
        suspiciousFactors.push({
            name: 'Suspicious Keywords Detected',
            detail: 'URL contains words like: login, verify, confirm, update, account, signin'
        });
    } else {
        safeFactors.push({
            name: 'No Suspicious Keywords',
            detail: 'No common phishing keywords found in URL'
        });
    }
    
    // 4. Dashes in Domain (Moderately suspicious)
    if (features.has_dash_in_domain === 1) {
        suspiciousFactors.push({
            name: 'Dashes in Domain',
            detail: 'Domain names with excessive dashes reduce brand trust (e.g., go-ogle.com)'
        });
    } else {
        safeFactors.push({
            name: 'Clean Domain Name',
            detail: 'Domain has no suspicious dashes or unusual characters'
        });
    }
    
    // 5. HTTPS Usage (Safe if present)
    if (features.uses_https === 1) {
        safeFactors.push({
            name: 'HTTPS Protocol',
            detail: 'Uses secure HTTPS connection - indicates legitimate website'
        });
    } else {
        suspiciousFactors.push({
            name: 'No HTTPS',
            detail: 'HTTP without encryption is often used by phishing sites'
        });
    }
    
    // 6. URL Length (Moderately suspicious if very long)
    if (features.url_length > 75) {
        suspiciousFactors.push({
            name: 'Very Long URL',
            detail: `URL length is ${features.url_length} chars - phishing URLs tend to be long to hide suspicious parts`
        });
    } else if (features.url_length < 20) {
        safeFactors.push({
            name: 'Short Clean URL',
            detail: `URL length is ${features.url_length} chars - legitimate URLs are usually concise`
        });
    }
    
    // 7. Subdomains (Moderate suspicion if many)
    if (features.num_subdomains > 2) {
        suspiciousFactors.push({
            name: 'Multiple Subdomains',
            detail: `Found ${features.num_subdomains} subdomains - unusual for most legitimate sites`
        });
    } else if (features.num_subdomains === 0) {
        safeFactors.push({
            name: 'Single Level Domain',
            detail: 'Clean domain structure - typical of legitimate websites'
        });
    }
    
    // 8. Special Characters (Moderate suspicion if many)
    if (features.num_special_chars > 3) {
        suspiciousFactors.push({
            name: 'Multiple Special Characters',
            detail: `Found ${features.num_special_chars} special characters - suspicious for legitimate URLs`
        });
    }
    
    // Populate the UI
    const suspiciousContainer = document.getElementById('suspiciousFactors');
    const safeContainer = document.getElementById('safeFactors');
    
    suspiciousContainer.innerHTML = '';
    safeContainer.innerHTML = '';
    
    // Add suspicious factors
    if (suspiciousFactors.length > 0) {
        suspiciousFactors.forEach(factor => {
            const div = document.createElement('div');
            div.className = 'factor-item suspicious';
            div.innerHTML = `
                <div class="factor-icon">🚨</div>
                <div class="factor-content">
                    <p class="factor-name">${factor.name}</p>
                    <p class="factor-detail">${factor.detail}</p>
                </div>
            `;
            suspiciousContainer.appendChild(div);
        });
    } else {
        // Show "No suspicious factors" message
        const noFactorsDiv = document.createElement('div');
        noFactorsDiv.className = 'no-factors-message';
        noFactorsDiv.innerHTML = `
            <div class="no-factors-icon">✅</div>
            <p class="no-factors-text">No suspicious factors detected! This URL appears clean.</p>
        `;
        suspiciousContainer.appendChild(noFactorsDiv);
    }
    
    // Add safe factors
    if (safeFactors.length > 0) {
        safeFactors.forEach(factor => {
            const div = document.createElement('div');
            div.className = 'factor-item safe';
            div.innerHTML = `
                <div class="factor-icon">✓</div>
                <div class="factor-content">
                    <p class="factor-name">${factor.name}</p>
                    <p class="factor-detail">${factor.detail}</p>
                </div>
            `;
            safeContainer.appendChild(div);
        });
    } else {
        // Show "No safe factors" message
        const noFactorsDiv = document.createElement('div');
        noFactorsDiv.className = 'no-factors-message';
        noFactorsDiv.innerHTML = `
            <div class="no-factors-icon">⚠️</div>
            <p class="no-factors-text">This URL has no safe characteristics detected.</p>
        `;
        safeContainer.appendChild(noFactorsDiv);
    }
    
    // Generate explanation based on analysis
    const explanation = generateConfidenceExplanation(
        suspiciousFactors.length,
        safeFactors.length,
        confidence,
        isPhishing
    );
    
    const explanationEl = document.getElementById('decisionExplanation');
    explanationEl.innerHTML = explanation;
}

/**
 * Generate a detailed explanation for the confidence score
 */
function generateConfidenceExplanation(suspiciousCount, safeCount, confidence, isPhishing) {
    const total = suspiciousCount + safeCount;
    
    // High confidence (80%+)
    if (confidence >= 80) {
        if (isPhishing) {
            return `⚠️ <strong>${suspiciousCount} suspicious factors</strong> detected with only ${safeCount} safe factors. <strong>High confidence this is a phishing URL.</strong> Avoid clicking or entering personal information.`;
        } else {
            return `✅ <strong>${safeCount} safe factors</strong> detected with only ${suspiciousCount} suspicious factors. <strong>High confidence this is a legitimate URL.</strong> This site appears to be safe.`;
        }
    }
    
    // Moderate-high confidence (70-79%)
    else if (confidence >= 70) {
        if (isPhishing) {
            return `⚠️ Found ${suspiciousCount} suspicious factors vs ${safeCount} safe factors. <strong>Fairly confident this is suspicious.</strong> Exercise caution before proceeding.`;
        } else {
            return `✅ Found ${safeCount} safe factors vs ${suspiciousCount} suspicious factors. <strong>Fairly confident this is legitimate.</strong> Appears safe to visit.`;
        }
    }
    
    // Moderate confidence (60-69%)
    else if (confidence >= 60) {
        if (isPhishing) {
            return `⚠️ ${suspiciousCount} suspicious factors slightly outweigh ${safeCount} safe factors. <strong>Moderate confidence in phishing detection.</strong> Proceed with caution.`;
        } else {
            return `✅ ${safeCount} safe factors slightly outweigh ${suspiciousCount} suspicious factors. <strong>Moderate confidence this is legitimate.</strong> Likely safe, but verify if entering sensitive data.`;
        }
    }
    
    // Uncertain (40-59%)
    else if (confidence >= 40) {
        return `❓ Mixed signals detected - ${suspiciousCount} suspicious vs ${safeCount} safe factors. <strong>The model is uncertain about this URL.</strong> Manual verification recommended before proceeding.`;
    }
    
    // Low confidence (<40%)
    else {
        return `❓ Low confidence either way - ${suspiciousCount} suspicious vs ${safeCount} safe factors. <strong>Insufficient data for a clear assessment.</strong> Please verify manually or contact the website admin.`;
    }
}

/**
 * Display and animate the process roadmap
 */
function displayProcessRoadmap(data) {
    const roadmapSteps = document.querySelectorAll('.roadmap-step');
    
    // Reset all steps to completed state
    roadmapSteps.forEach((step, index) => {
        step.classList.remove('in-progress', 'pending');
        step.classList.add('completed');
    });
    
    // Animate steps one by one
    const steps = [
        { name: '1', duration: 300 },
        { name: '2', duration: 300 },
        { name: '3', duration: 300 },
        { name: '4', duration: 300 },
        { name: '5', duration: 300 }
    ];
    
    let delay = 0;
    steps.forEach((step, index) => {
        setTimeout(() => {
            if (roadmapSteps[index * 2]) { // Account for connectors
                roadmapSteps[index * 2].classList.remove('in-progress');
                roadmapSteps[index * 2].classList.add('completed');
                
                // Add checkmark animation
                const stepNum = roadmapSteps[index * 2].querySelector('.step-number');
                if (stepNum) {
                    stepNum.style.animation = 'none';
                    setTimeout(() => {
                        stepNum.textContent = '✓';
                        stepNum.style.fontSize = '1.2rem';
                    }, 100);
                }
            }
        }, delay);
        delay += step.duration + 100;
    });
}

/**
 * Display extracted features
 */
function displayFeatures(features) {
    const featuresGrid = document.getElementById('featuresGrid');
    featuresGrid.innerHTML = '';
    
    // Feature display names and icons with descriptions
    const featureInfo = {
        'url_length': { 
            label: 'URL Length', 
            icon: '📏', 
            value: features.url_length,
            description: 'Phishing URLs are often longer'
        },
        'has_at_symbol': { 
            label: 'Has @ Symbol', 
            icon: '⚠️', 
            value: features.has_at_symbol ? 'Yes ⚠️' : 'No ✓', 
            description: 'Used to hide real domain'
        },
        'has_dash_in_domain': { 
            label: 'Dashes in Domain', 
            icon: '🔗', 
            value: features.has_dash_in_domain ? 'Yes ⚠️' : 'No ✓', 
            description: 'Reduces brand trust'
        },
        'num_subdomains': { 
            label: 'Subdomains Count', 
            icon: '🌐', 
            value: features.num_subdomains,
            description: 'Many subdomains = suspicious'
        },
        'uses_https': { 
            label: 'Uses HTTPS', 
            icon: '🔒', 
            value: features.uses_https ? 'Yes ✓' : 'No ⚠️', 
            description: 'Secure connection indicator'
        },
        'has_ip_address': { 
            label: 'IP Address', 
            icon: '🔢', 
            value: features.has_ip_address ? 'Yes ⚠️' : 'No ✓', 
            description: 'Direct IP is suspicious'
        },
        'num_slashes': { 
            label: 'Path Slashes', 
            icon: '/', 
            value: features.num_slashes,
            description: 'Directory depth in URL'
        },
        'num_dots': { 
            label: 'Dots Count', 
            icon: '•', 
            value: features.num_dots,
            description: 'Separators in URL'
        },
        'num_special_chars': { 
            label: 'Special Characters', 
            icon: '✦', 
            value: features.num_special_chars,
            description: 'Unusual chars indicate phishing'
        },
        'domain_length': { 
            label: 'Domain Length', 
            icon: '📊', 
            value: features.domain_length,
            description: 'Excessively long = suspicious'
        },
        'has_suspicious_keywords': { 
            label: 'Suspicious Keywords', 
            icon: '🔍', 
            value: features.has_suspicious_keywords ? 'Yes ⚠️' : 'No ✓', 
            description: 'login, verify, confirm, etc.'
        }
    };
    
    // Create feature items with better styling
    for (const [key, info] of Object.entries(featureInfo)) {
        const featureItem = document.createElement('div');
        featureItem.className = 'feature-item';
        
        // Add warning class for suspicious values
        const valueStr = String(info.value);
        if (valueStr.includes('⚠️')) {
            featureItem.classList.add('suspicious');
        } else if (valueStr.includes('✓')) {
            featureItem.classList.add('safe');
        }
        
        featureItem.innerHTML = `
            <div class="feature-header">
                <span class="feature-icon-badge">${info.icon}</span>
                <span class="feature-item-label">${info.label}</span>
            </div>
            <div class="feature-body">
                <span class="feature-item-value">${info.value}</span>
                <p class="feature-description">${info.description}</p>
            </div>
        `;
        featuresGrid.appendChild(featureItem);
    }
    
    // Automatically open features section when results are displayed
    featuresDetails.classList.add('show');
    const arrow = document.getElementById('toggleArrow');
    arrow.style.transform = 'rotate(180deg)';
}

/**
 * Toggle features details visibility
 */
function toggleFeatures() {
    featuresDetails.classList.toggle('show');
    const arrow = document.getElementById('toggleArrow');
    
    if (featuresDetails.classList.contains('show')) {
        arrow.style.transform = 'rotate(180deg)';
    } else {
        arrow.style.transform = 'rotate(0deg)';
    }
}

/**
 * Display detailed scan results with domain, hosting, location, and threat info
 */
function displayScanResults(data) {
    const scanSection = document.getElementById('scanResultsSection');
    if (!scanSection) return;
    
    // Domain Information
    document.getElementById('scanDomain').textContent = data.domain_info?.domain || '-';
    document.getElementById('scanIp').textContent = data.domain_info?.ip_address || '-';
    document.getElementById('scanTld').textContent = data.domain_info?.tld || '-';
    document.getElementById('scanProtocol').textContent = (data.domain_info?.protocol || 'http').toUpperCase();
    
    // Brand & Hosting
    document.getElementById('scanBrand').textContent = data.brand || 'Unknown';
    document.getElementById('scanHosting').textContent = data.hosting?.provider || '-';
    document.getElementById('scanHostingType').textContent = data.hosting?.type || '-';
    document.getElementById('scanAsn').textContent = data.hosting?.asn || '-';
    
    // Location
    document.getElementById('scanCountry').textContent = data.location?.country || '-';
    document.getElementById('scanCity').textContent = data.location?.city || '-';
    
    // Certificate
    document.getElementById('scanCertIssuedTo').textContent = data.certificate?.issued_to || '-';
    document.getElementById('scanCertIssuedBy').textContent = data.certificate?.issued_by || '-';
    document.getElementById('scanCertValid').textContent = data.certificate?.valid ? '✅ Yes' : '❌ No';
    document.getElementById('scanCertTrusted').textContent = data.certificate?.is_trusted ? '✅ Yes' : '❌ No';
    
    // Threat Intelligence
    document.getElementById('scanPastPhishHost').textContent = data.threat_intelligence?.past_phish_on_host || 0;
    document.getElementById('scanPastPhishIp').textContent = data.threat_intelligence?.past_phish_on_ip || 0;
    document.getElementById('scanPhishingKits').textContent = data.threat_intelligence?.phishing_kits || 0;
    document.getElementById('scanSpamReports').textContent = data.threat_intelligence?.spam_reports || 0;
    
    // Scan Details
    document.getElementById('scanDate').textContent = data.scan_results?.detection_date || '-';
    document.getElementById('scanJobId').textContent = data.scan_results?.job_id || '-';
    document.getElementById('scanLogos').textContent = data.scan_settings?.logos_detected || 0;
}

/**
 * Display Explainable AI explanations with reasoning
 */
function displayExplanations(explanation) {
    if (!explanation) return;
    
    // Display summary
    const summaryEl = document.getElementById('explanationSummary');
    if (summaryEl) {
        summaryEl.textContent = explanation.summary;
    }
    
    // Display danger reasons
    const dangerContainer = document.getElementById('dangerReasonsContainer');
    const dangerReasonsEl = document.getElementById('dangerReasons');
    
    if (explanation.danger_reasons && explanation.danger_reasons.length > 0) {
        dangerContainer.classList.remove('hidden');
        dangerReasonsEl.innerHTML = '';
        
        explanation.danger_reasons.forEach(reason => {
            const reasonCard = document.createElement('div');
            reasonCard.className = 'reason-card danger';
            reasonCard.innerHTML = `
                <div class="reason-icon">${reason.icon}</div>
                <h4 class="reason-title">${reason.reason}</h4>
                <p class="reason-explanation">${reason.explanation}</p>
                <span class="reason-severity ${reason.severity}">${reason.severity}</span>
            `;
            dangerReasonsEl.appendChild(reasonCard);
        });
    } else {
        dangerContainer.classList.add('hidden');
    }
    
    // Display safe reasons
    const safeContainer = document.getElementById('safeReasonsContainer');
    const safeReasonsEl = document.getElementById('safeReasons');
    
    if (explanation.safe_reasons && explanation.safe_reasons.length > 0) {
        safeContainer.classList.remove('hidden');
        safeReasonsEl.innerHTML = '';
        
        explanation.safe_reasons.forEach(reason => {
            const reasonCard = document.createElement('div');
            reasonCard.className = 'reason-card safe';
            reasonCard.innerHTML = `
                <div class="reason-icon">${reason.icon}</div>
                <h4 class="reason-title">${reason.reason}</h4>
                <p class="reason-explanation">${reason.explanation}</p>
                <span class="reason-severity ${reason.severity}">${reason.severity}</span>
            `;
            safeReasonsEl.appendChild(reasonCard);
        });
    } else {
        safeContainer.classList.add('hidden');
    }
}

/**
 * Reset features toggle to closed state
 */
function resetFeaturesToggle() {
    featuresDetails.classList.remove('show');
    const arrow = document.getElementById('toggleArrow');
    arrow.style.transform = 'rotate(0deg)';
}

/**
 * Display all analysis charts
 */
function displayCharts(data) {
    // Destroy previous charts if they exist
    Object.keys(charts).forEach(key => {
        if (charts[key]) {
            try {
                charts[key].destroy();
            } catch (e) {
                console.warn('Error destroying chart:', e);
            }
            charts[key] = null;
        }
    });
    
    // Draw all charts with error handling
    try {
        drawConfidenceChart(data);
    } catch (e) {
        console.error('Error drawing confidence chart:', e);
    }
    
    try {
        drawRiskFactorsChart(data);
    } catch (e) {
        console.error('Error drawing risk factors chart:', e);
    }
    
    try {
        drawFeaturesChart(data);
    } catch (e) {
        console.error('Error drawing features chart:', e);
    }
    
    try {
        drawThreatChart(data);
    } catch (e) {
        console.error('Error drawing threat chart:', e);
    }
}

/**
 * Draw confidence score pie chart
 */
function drawConfidenceChart(data) {
    const ctx = document.getElementById('confidenceChart');
    if (!ctx) {
        console.error('Confidence chart canvas not found');
        return;
    }
    
    const confidence = data.confidence || 50;
    const inverse = 100 - confidence;
    const colors = data.prediction === 'Phishing' 
        ? ['#ef4444', '#10b981']  // Red for phishing, green for safe
        : ['#10b981', '#ef4444']; // Green for safe, red for phishing
    
    const labels = data.prediction === 'Phishing'
        ? ['Phishing Score', 'Safe Score']
        : ['Safe Score', 'Phishing Score'];
    
    if (charts.confidence) {
        charts.confidence.destroy();
    }
    
    charts.confidence = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: [confidence, inverse],
                backgroundColor: colors,
                borderColor: ['#ffffff', '#ffffff'],
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#374151',
                        font: { size: 12, weight: 'bold' },
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 },
                    callbacks: {
                        label: function(context) {
                            return context.label + ': ' + context.parsed + '%';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Draw risk factors bar chart
 */
function drawRiskFactorsChart(data) {
    const ctx = document.getElementById('riskFactorsChart');
    if (!ctx) {
        console.error('Risk factors chart canvas not found');
        return;
    }
    
    // Count suspicious and safe factors
    let suspiciousCount = 0;
    let safeCount = 0;
    
    // Check each feature
    if (data.features.has_at_symbol === 1) suspiciousCount++;
    else safeCount++;
    
    if (data.features.has_ip_address === 1) suspiciousCount++;
    else safeCount++;
    
    if (data.features.has_suspicious_keywords === 1) suspiciousCount++;
    else safeCount++;
    
    if (data.features.has_dash_in_domain === 1) suspiciousCount++;
    else safeCount++;
    
    if (data.features.uses_https === 0) suspiciousCount++;
    else safeCount++;
    
    if (data.features.url_length > 75) suspiciousCount++;
    else safeCount++;
    
    if (data.features.num_subdomains > 2) suspiciousCount++;
    else safeCount++;
    
    if (data.features.num_special_chars > 3) suspiciousCount++;
    else safeCount++;
    
    if (charts.riskFactors) {
        charts.riskFactors.destroy();
    }
    
    charts.riskFactors = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Suspicious Factors', 'Safe Factors'],
            datasets: [{
                label: 'Factor Count',
                data: [suspiciousCount, safeCount],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.7)',  // Red for suspicious
                    'rgba(16, 185, 129, 0.7)' // Green for safe
                ],
                borderColor: [
                    '#ef4444',
                    '#10b981'
                ],
                borderWidth: 2,
                borderRadius: 8
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            return 'Factors: ' + context.parsed.x;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 10,
                    ticks: {
                        color: '#6b7280',
                        font: { size: 11 }
                    },
                    grid: {
                        color: 'rgba(209, 213, 219, 0.3)'
                    }
                },
                y: {
                    ticks: {
                        color: '#374151',
                        font: { size: 12, weight: 'bold' }
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Draw URL features radar chart
 */
function drawFeaturesChart(data) {
    const ctx = document.getElementById('featuresChart');
    if (!ctx) {
        console.error('Features chart canvas not found');
        return;
    }
    
    const features = data.features;
    
    // Feature values (0 or 1, normalize to 0-100)
    const featureValues = [
        features.uses_https * 100,           // HTTPS usage
        (1 - features.has_at_symbol) * 100,  // No @ symbol
        (1 - features.has_ip_address) * 100, // No IP address
        (1 - features.has_dash_in_domain) * 100,  // No dashes
        (1 - features.has_suspicious_keywords) * 100, // No suspicious keywords
        Math.max(0, (100 - (features.url_length * 1.3))), // URL length score
    ];
    
    if (charts.features) {
        charts.features.destroy();
    }
    
    charts.features = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: [
                'HTTPS Used',
                'No @ Symbol',
                'No IP Address',
                'No Dashes',
                'No Suspicious Words',
                'URL Length OK'
            ],
            datasets: [{
                label: 'Safety Score',
                data: featureValues,
                borderColor: '#6366f1',
                backgroundColor: 'rgba(99, 102, 241, 0.2)',
                pointBackgroundColor: '#6366f1',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 5,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#374151',
                        font: { size: 12, weight: 'bold' },
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            return 'Score: ' + Math.round(context.parsed.r) + '/100';
                        }
                    }
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: '#9ca3af',
                        font: { size: 10 }
                    },
                    grid: {
                        color: 'rgba(209, 213, 219, 0.4)'
                    },
                    pointLabels: {
                        color: '#374151',
                        font: { size: 11, weight: 'bold' }
                    }
                }
            }
        }
    });
}

/**
 * Draw threat intelligence doughnut chart
 */
function drawThreatChart(data) {
    const canvasElement = document.getElementById('threatChart');
    if (!canvasElement) {
        console.error('Threat chart canvas not found');
        return;
    }
    
    try {
        const threats = data.threat_intelligence || {};
        
        const threatData = [
            parseInt(threats.past_phish_on_host) || 0,
            parseInt(threats.past_phish_on_ip) || 0,
            parseInt(threats.phishing_kits) || 0,
            parseInt(threats.spam_reports) || 0
        ];
        
        // Check if all values are zero
        const hasData = threatData.some(v => v > 0);
        
        // Determine color based on threat level
        const maxThreat = Math.max(...threatData);
        let color = '#10b981'; // Green
        
        if (maxThreat > 5) color = '#ec4899'; // Pink
        if (maxThreat > 10) color = '#ef4444'; // Red
        
        // Create proper chart data
        const chartData = {
            labels: [
                'Past Phish on Host',
                'Past Phish on IP',
                'Phishing Kits',
                'Spam Reports'
            ],
            datasets: [{
                data: threatData,
                backgroundColor: [
                    'rgba(239, 68, 68, 0.7)',     // Red
                    'rgba(236, 72, 153, 0.7)',    // Pink
                    'rgba(251, 146, 60, 0.7)',    // Orange
                    'rgba(248, 113, 113, 0.7)'    // Light red
                ],
                borderColor: [
                    '#ef4444',
                    '#ec4899',
                    '#fb923c',
                    '#f87171'
                ],
                borderWidth: 2
            }]
        };
        
        if (charts.threat) {
            charts.threat.destroy();
        }
        
        charts.threat = new Chart(canvasElement, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#374151',
                            font: { size: 11, weight: 'bold' },
                            padding: 12
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                return context.label + ': ' + context.parsed;
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error drawing threat chart:', error);
    }
}

/**
 * Show loading animation
 */
function showLoading() {
    resultSection.classList.add('hidden');
    loadingSection.classList.remove('hidden');
    checkBtn.disabled = true;
}

/**
 * Hide loading animation
 */
function hideLoading() {
    loadingSection.classList.add('hidden');
    checkBtn.disabled = false;
}

/**
 * Show error message
 */
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.add('show');
}

/**
 * Clear error message
 */
function clearError() {
    errorMessage.textContent = '';
    errorMessage.classList.remove('show');
}

/**
 * Reset form to initial state
 */
function resetForm() {
    urlInput.value = '';
    urlInput.focus();
    resultSection.classList.add('hidden');
    loadingSection.classList.add('hidden');
    clearError();
}

/**
 * Copy result to clipboard
 */
function copyResult() {
    if (!lastResult) return;
    
    const resultText = `
URL Analysis Result
===================
URL: ${lastResult.url}
Prediction: ${lastResult.prediction}
Confidence: ${lastResult.confidence}%

Features:
- URL Length: ${lastResult.features.url_length}
- Has @ Symbol: ${lastResult.features.has_at_symbol ? 'Yes' : 'No'}
- Dashes in Domain: ${lastResult.features.has_dash_in_domain ? 'Yes' : 'No'}
- Subdomains: ${lastResult.features.num_subdomains}
- Uses HTTPS: ${lastResult.features.uses_https ? 'Yes' : 'No'}
- Has IP Address: ${lastResult.features.has_ip_address ? 'Yes' : 'No'}

Generated by PhishGuard URL Detector
    `.trim();
    
    navigator.clipboard.writeText(resultText).then(() => {
        // Show feedback
        const originalText = shareBtn.textContent;
        shareBtn.textContent = '✓ Copied!';
        shareBtn.style.background = 'var(--success-color)';
        shareBtn.style.color = 'white';
        
        setTimeout(() => {
            shareBtn.textContent = originalText;
            shareBtn.style.background = '';
            shareBtn.style.color = '';
        }, 2000);
    }).catch(() => {
        alert('Failed to copy result');
    });
}

/**
 * Example URLs for testing
 * Uncomment to add quick test examples
 */
function loadExampleURL(url) {
    urlInput.value = url;
    handleCheckURL();
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + L: Focus on URL input
    if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        urlInput.focus();
    }
    
    // Ctrl/Cmd + Enter: Check URL
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        handleCheckURL();
    }
});

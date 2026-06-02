

Chart.defaults.color = '#94a3b8';           // Text color (muted gray)
Chart.defaults.borderColor = '#2a3050';     // Grid line color
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.pointStyle = 'circle';


function createPieChart() {
    const ctx = document.getElementById('pieChart').getContext('2d');

    new Chart(ctx, {
        type: 'doughnut',   // Doughnut looks more modern than pie
        data: {
            labels: ['Normal Traffic', 'Attack Traffic'],
            datasets: [{
                data: [RESULTS.normalCount, RESULTS.attackCount],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.8)',   // Green for normal
                    'rgba(239, 68, 68, 0.8)'     // Red for attacks
                ],
                borderColor: [
                    'rgba(16, 185, 129, 1)',
                    'rgba(239, 68, 68, 1)'
                ],
                borderWidth: 2,
                hoverOffset: 8,                  // Expand on hover
                spacing: 3                       // Gap between segments
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '55%',                       // Doughnut hole size
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: { size: 13, weight: '500' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleFont: { size: 14, weight: '600' },
                    bodyFont: { size: 13 },
                    padding: 12,
                    cornerRadius: 8,
                    displayColors: true,
                    callbacks: {
                        // Show percentage in tooltip
                        label: function (context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return ` ${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1200,
                easing: 'easeOutQuart'
            }
        }
    });
}




function createBarChart() {
    const ctx = document.getElementById('barChart').getContext('2d');

    // Get attack type names and counts from the data
    const attackTypes = Object.keys(RESULTS.attackDistribution);
    const attackCounts = Object.values(RESULTS.attackDistribution);

    // Color palette for each attack type
    const colors = {
        'DOS': { bg: 'rgba(239, 68, 68, 0.7)', border: 'rgba(239, 68, 68, 1)' },
        'PROBE': { bg: 'rgba(245, 158, 11, 0.7)', border: 'rgba(245, 158, 11, 1)' },
        'R2L': { bg: 'rgba(124, 58, 237, 0.7)', border: 'rgba(124, 58, 237, 1)' },
        'U2R': { bg: 'rgba(59, 130, 246, 0.7)', border: 'rgba(59, 130, 246, 1)' }
    };

    // Map colors to each attack type
    const bgColors = attackTypes.map(t => (colors[t] || colors['DOS']).bg);
    const borderColors = attackTypes.map(t => (colors[t] || colors['DOS']).border);

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: attackTypes,
            datasets: [{
                label: 'Number of Records',
                data: attackCounts,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 2,
                borderRadius: 8,            // Rounded bar corners
                borderSkipped: false,       // Round all corners
                barPercentage: 0.6,         // Bar width
                categoryPercentage: 0.7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false           // Hide legend (labels are on X axis)
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleFont: { size: 14, weight: '600' },
                    bodyFont: { size: 13 },
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: function (context) {
                            return ` Count: ${context.parsed.y} records`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        font: { size: 12, weight: '600' }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(42, 48, 80, 0.5)',
                        drawBorder: false
                    },
                    ticks: {
                        stepSize: 1,
                        font: { size: 11 }
                    }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart',
                delay: function (context) {
                    // Stagger the bars appearing
                    return context.dataIndex * 150;
                }
            }
        }
    });
}



function createComparisonChart() {
    const ctx = document.getElementById('comparisonChart').getContext('2d');

    // Extract model names and accuracies
    const modelNames = RESULTS.modelComparison.map(m => m.name);
    const accuracies = RESULTS.modelComparison.map(m => (m.accuracy * 100).toFixed(1));

    // Colors: highlight Random Forest (our deployed model)
    const bgColors = modelNames.map(name =>
        name === 'Random Forest'
            ? 'rgba(0, 229, 255, 0.7)'       // Cyan for RF (selected)
            : 'rgba(100, 116, 139, 0.5)'     // Gray for others
    );
    const borderColors = modelNames.map(name =>
        name === 'Random Forest'
            ? 'rgba(0, 229, 255, 1)'
            : 'rgba(100, 116, 139, 0.8)'
    );

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: modelNames,
            datasets: [{
                label: 'Accuracy (%)',
                data: accuracies,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 2,
                borderRadius: 8,
                borderSkipped: false,
                barPercentage: 0.5,
                categoryPercentage: 0.7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',              // Horizontal bars
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleFont: { size: 14, weight: '600' },
                    bodyFont: { size: 13 },
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: function (context) {
                            return ` Accuracy: ${context.parsed.x}%`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    min: 0,
                    max: 100,
                    grid: {
                        color: 'rgba(42, 48, 80, 0.5)',
                        drawBorder: false
                    },
                    ticks: {
                        callback: val => val + '%',
                        font: { size: 11 }
                    }
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        font: { size: 12, weight: '500' }
                    }
                }
            },
            animation: {
                duration: 1200,
                easing: 'easeOutQuart',
                delay: function (context) {
                    return context.dataIndex * 200;
                }
            }
        }
    });
}


document.addEventListener('DOMContentLoaded', function () {
    // Small delay so animations feel sequential
    setTimeout(createPieChart, 200);
    setTimeout(createBarChart, 400);
    setTimeout(createComparisonChart, 600);

    // Animate summary card values (count-up effect)
    animateCounters();
});



function animateCounters() {
    const counters = [
        { element: document.getElementById('total-records'), target: RESULTS.normalCount + RESULTS.attackCount },
        { element: document.getElementById('normal-count'), target: RESULTS.normalCount },
        { element: document.getElementById('attack-count'), target: RESULTS.attackCount }
    ];

    counters.forEach(counter => {
        if (!counter.element) return;

        const target = counter.target;
        const duration = 1500;        // Animation duration in ms
        const startTime = Date.now();

        function update() {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Ease-out function for smooth deceleration
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(eased * target);

            counter.element.textContent = current.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                counter.element.textContent = target.toLocaleString();
            }
        }

        // Start animation after a small delay
        setTimeout(update, 300);
    });
}

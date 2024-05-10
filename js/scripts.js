// SIDEBAR TOGGLE

let sidebarOpen = false;
const sidebar = document.getElementById('sidebar');

function openSidebar() {
  if (!sidebarOpen) {
    sidebar.classList.add('sidebar-responsive');
    sidebarOpen = true;
  }
}

function closeSidebar() {
  if (sidebarOpen) {
    sidebar.classList.remove('sidebar-responsive');
    sidebarOpen = false;
  }
}

// ---------- CHARTS ----------

// BAR CHART

let barChart;
let isRendering = false;

function updateBarGraph(serviceNames,serviceCounts){

  // Check if rendering is already in progress
  if (isRendering) {
    return;
  }
  
  const barChartOptions = {
    series: [
      {
        data: serviceCounts,
        name: 'Frequency',
      },
    ],
    chart: {
      type: 'bar',
      background: 'transparent',
      height: 350,
      toolbar: {
        show: false,
      },
    },
    colors: ['#2962ff', '#d50000', '#2e7d32', '#ff6d00', '#583cb3'],
    plotOptions: {
      bar: {
        distributed: true,
        borderRadius: 4,
        horizontal: false,
        columnWidth: '40%',
      },
    },
    dataLabels: {
      enabled: false,
    },
    fill: {
      opacity: 1,
    },
    grid: {
      borderColor: '#55596e',
      yaxis: {
        lines: {
          show: true,
        },
      },
      xaxis: {
        lines: {
          show: true,
        },
      },
    },
    legend: {
      labels: {
        colors: '#f5f7ff',
      },
      show: true,
      position: 'top',
    },
    stroke: {
      colors: ['transparent'],
      show: true,
      width: 2,
    },
    tooltip: {
      shared: true,
      intersect: false,
      theme: 'dark',
    },
    xaxis: {
      categories: serviceNames,
      title: {
        style: {
          color: '#f5f7ff',
        },
      },
      axisBorder: {
        show: true,
        color: '#55596e',
      },
      axisTicks: {
        show: true,
        color: '#55596e',
      },
      labels: {
        style: {
          colors: '#f5f7ff',
        },
      },
    },
    yaxis: {
      title: {
        text: 'Count',
        style: {
          color: '#f5f7ff',
        },
      },
      axisBorder: {
        color: '#55596e',
        show: true,
      },
      axisTicks: {
        color: '#55596e',
      show: true,
      },
      labels: {
        style: {
          colors: '#f5f7ff',
        },
      },
    },
  };

  if (!barChart) {
  barChart = new ApexCharts(
    document.querySelector('#bar-chart'),
    barChartOptions
  );
  barChart.render();
  }
  else{
    // Update existing chart
    barChart.updateOptions(barChartOptions);
  }

  // Reset rendering flag after a short delay
  setTimeout(() => {
    isRendering = false;
  }, 10);

}

let lineChart;
let isRenderingLineGraph = false;
let debounceTimer;

function updateLineGraph(seriesData){

  // Check if rendering is already in progress or if a debounce timer is active
  if (isRenderingLineGraph || debounceTimer) {
    clearTimeout(debounceTimer); // Clear any existing debounce timer
  }

  

  // Set a new debounce timer
  debounceTimer = setTimeout(() => {
  const areaChartOptions = {
    series: seriesData,
    chart: {
      type: 'area',
      background: 'transparent',
      height: 350,
      stacked: false,
      toolbar: {
        show: false,
      },
    },
    colors: generateColors(seriesData.length),
    labels: ['1 min','2 min','3 min','4 min','5 min','6 min','7 min'],
    dataLabels: {
      enabled: false,
    },
    fill: {
      gradient: {
        opacityFrom: 0.4,
        opacityTo: 0.1,
        shadeIntensity: 1,
        stops: [0, 100],
        type: 'vertical',
      },
      type: 'gradient',
    },
    grid: {
      borderColor: '#55596e',
      yaxis: {
        lines: {
          show: true,
        },
      },
      xaxis: {
        lines: {
          show: true,
        },
      },
    },
    legend: {
      labels: {
        colors: '#f5f7ff',
      },
      show: true,
      position: 'top',
    },
    markers: {
      size: 6,
      strokeColors: '#1b2635',
      strokeWidth: 3,
    },
    stroke: {
      curve: 'smooth',
    },
    xaxis: {
      axisBorder: {
        color: '#55596e',
        show: true,
      },
      axisTicks: {
        color: '#55596e',
        show: true,
      },
      labels: {
        offsetY: 5,
        style: {
          colors: '#f5f7ff',
        },
      },
    },
    yaxis: [
      {
        title: {
          text: 'Packets',
          style: {
            color: '#f5f7ff',
          },
        },
        labels: {
          style: {
            colors: ['#f5f7ff'],
          },
        },
      },
      {
        opposite: true,
        title: {
          text: 'Threshold',
          style: {
            color: '#f5f7ff',
          },
        },
        labels: {
          style: {
            colors: ['#f5f7ff'],
          },
        },
      },
    ],
    tooltip: {
      shared: true,
      intersect: false,
      theme: 'dark',
    },
  };
  

  if (!lineChart) {
    const areaChart = new ApexCharts(
      document.querySelector('#area-chart'),
      areaChartOptions
    );
    areaChart.render();
    lineChart = areaChart;
  } else {
    lineChart.updateSeries(areaChartOptions.series);
  }

  isRenderingLineGraph = false; // Reset rendering flag
}, 300); // Adjust the debounce delay as needed (e.g., 300 milliseconds)
}
// AREA CHART

// Function to generate dynamic colors based on the number of IP addresses
function generateColors(numColors) {
  const colors = ['#00ab57', '#d50000']; // Default colors
  const additionalColors = ['#ff8f00', '#6200ea', '#e91e63', '#9c27b0', '#3f51b5', '#00bcd4', '#009688', '#4caf50']; // Additional colors
  const totalColors = colors.concat(additionalColors.slice(0, numColors - colors.length));
  return totalColors;
}



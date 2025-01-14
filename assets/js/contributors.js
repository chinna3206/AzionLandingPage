 window.onscroll = function () {
    var winScroll = document.body.scrollTop || document.documentElement.scrollTop;
    var height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    var scrolled = (winScroll / height) * 100;
    document.getElementById("progressBar").style.width = scrolled + "%";
  };

 document.addEventListener("DOMContentLoaded", function () {
    const coords = { x: 0, y: 0 };
    const circles = document.querySelectorAll(".circle");

    circles.forEach(function (circle) {
      circle.x = 0;
      circle.y = 0;
    });

    window.addEventListener("mousemove", function (e) {
      coords.x = e.pageX;
      coords.y = e.pageY - window.scrollY; // Adjust for vertical scroll position
    });

    function animateCircles() {
      let x = coords.x;
      let y = coords.y;

      circles.forEach(function (circle, index) {
        circle.style.left = `${x - 12}px`;
        circle.style.top = `${y - 12}px`;
        circle.style.transform = `scale(${(circles.length - index) / circles.length})`;

        const nextCircle = circles[index + 1] || circles[0];
        circle.x = x;
        circle.y = y;

        x += (nextCircle.x - x) * 0.3;
        y += (nextCircle.y - y) * 0.3;
      });

      requestAnimationFrame(animateCircles);
    }

    animateCircles();
  });

  document.addEventListener('DOMContentLoaded', function () {
    const contributorsContainer = document.getElementById('contributors');

    async function fetchContributors() {
        try {
            let page = 1;
            const perPage = 100;
            let totalContributors = [];

            while (true) {
                const response = await fetch(`https://api.github.com/repos/ayush-that/VignanAIDynamics /contributors?per_page=${perPage}&page=${page}`);
                const contributors = await response.json();

                if (contributors.length === 0) break;

                totalContributors = totalContributors.concat(contributors);
                page++;
            }

            totalContributors.forEach(contributor => {
                const contributorCard = document.createElement('a');
                contributorCard.href = contributor.html_url;
                contributorCard.target = '_blank';
                contributorCard.className = 'contributor-card';
                contributorCard.innerHTML = `
            <img src="${contributor.avatar_url}" alt="${contributor.login}">
            <h2 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">${contributor.login}</h2>
            <p class="text-gray-700 dark:text-gray-400">Contributions: ${contributor.contributions}</p>
            <p class="text-gray-700 dark:text-gray-400 flex-center"><i class="fab fa-github mr-1"></i> GitHub Profile</p>
        `;
                contributorsContainer.appendChild(contributorCard);
            });
        } catch (error) {
            console.error('Error fetching contributors:', error);
        }
    }

    fetchContributors();
});

 document.getElementById('unique-subscribe-form').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent form from submitting normally

    // Show popup message
    var messageDiv = document.getElementById('unique-message');
    messageDiv.style.display = 'block';
    
    // Reset existing animation
    var borderAnimationDiv = messageDiv.querySelector('.border-animation');
    borderAnimationDiv.style.animation = 'none';
    borderAnimationDiv.offsetHeight; // Trigger reflow to restart the animation
    borderAnimationDiv.style.animation = 'borderAnimation 3s linear forwards';

    // Hide popup message after 10 seconds
    setTimeout(function() {
      messageDiv.style.display = 'none';
    }, 3000); // 10 seconds

    // Reset form
    this.reset();
  });

  document.getElementById("copyright-year").textContent =
  new Date().getFullYear();

  


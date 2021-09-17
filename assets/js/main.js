(() => {
  // Theme switch
  const body = document.body;
  const lamp = document.getElementById("mode");
  const sapienza_logo_dark = document.getElementById('dark_logo')
  const sapienza_logo_light = document.getElementById('light_logo')

  const toggleTheme = (state) => {
    if (state === "dark") {
      localStorage.setItem("theme", "light");
      body.removeAttribute("data-theme");

      if (sapienza_logo_light.display === 'none'){
        sapienza_logo_light.display = 'block'
        sapienza_logo_dark.display = 'none'
      }

    } else if (state === "light") {
      localStorage.setItem("theme", "dark");
      body.setAttribute("data-theme", "dark");

      if (sapienza_logo_dark.display === 'none'){
        sapienza_logo_dark.display = 'block'
        sapienza_logo_light.display = 'none'
      }

    } else {
      initTheme(state);
    }
  };

  lamp.addEventListener("click", () =>
    toggleTheme(localStorage.getItem("theme"))
  );

  // Blur the content when the menu is open
  const cbox = document.getElementById("menu-trigger");

  cbox.addEventListener("change", function () {
    const area = document.querySelector(".wrapper");
    this.checked
      ? area.classList.add("blurry")
      : area.classList.remove("blurry");
  });
})();

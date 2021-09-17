(() => {
  // Theme switch
  const body = document.body;
  const lamp = document.getElementById("mode");
  const sapienza_logo_dark = document.getElementById('dark_theme')
  const sapienza_logo_light = document.getElementById('light_theme')

  const toggleTheme = (state) => {
    if (state === "dark") {
      localStorage.setItem("theme", "light");
      body.removeAttribute("data-theme");
      sapienza_logo_light.classList.remove('display')
      sapienza_logo_dark.classList.add('display', 'none')
    } else if (state === "light") {
      localStorage.setItem("theme", "dark");
      body.setAttribute("data-theme", "dark");
      sapienza_logo_light.classList.add('display', 'none')
      sapienza_logo_dark.classList.remove('display')
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

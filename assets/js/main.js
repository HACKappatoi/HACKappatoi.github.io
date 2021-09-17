(() => {
  // Theme switch
  const body = document.body;
  const lamp = document.getElementById("mode");
  localStorage.setItem('theme', 'dark')

  const toggleTheme = (state) => {
    if (state === "dark" || state === 'light') {
      localStorage.setItem("theme", "dark");
      body.removeAttribute("data-theme");

    } /*else if (state === "light") {
      localStorage.setItem("theme", "dark");
      body.setAttribute("data-theme", "dark");

    }*/ else {
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

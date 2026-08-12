const routes = [{ path: "/dashboard" }];

fetch("/api.json")
  .then((response) => response.json())
  .then((value) => fetch(`/detail.json?runnerId=${value.runnerId}`));

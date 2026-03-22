export const signupUser = (user) => {
  localStorage.setItem("user", JSON.stringify(user));
};

export const loginUser = (userId, username) => {
  localStorage.setItem("user_id", userId);
  localStorage.setItem("username", username);
  localStorage.setItem("loggedIn", "true");
};

export const logoutUser = () => {
  localStorage.clear();
};

export const isAuthenticated = () => {
  return localStorage.getItem("loggedIn") === "true";
};

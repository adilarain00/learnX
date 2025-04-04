import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import { userLoggedIn } from "../auth/authSlice";

export const apiSlice = createApi({
  reducerPath: "api",
  baseQuery: fetchBaseQuery({
    baseUrl: process.env.NEXT_PUBLIC_SERVER_URI,
    credentials: "include", // Ensure cookies are included
    prepareHeaders: (headers) => {
      const token = localStorage.getItem("access_token"); // Get token from localStorage
      if (token) {
        headers.set("Authorization", `Bearer ${token}`);
      }
      return headers;
    },
  }),
  endpoints: (builder) => ({
    refreshAccessToken: builder.query({
      query: () => ({
        url: "refresh",
        method: "GET",
        credentials: "include",
      }),
    }),

    loadUser: builder.query({
      query: () => ({
        url: "me",
        method: "GET",
        credentials: "include",
      }),
      async onQueryStarted(arg, { queryFulfilled, dispatch }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(
            userLoggedIn({
              accessToken: data.accessToken,
              user: data.user,
            })
          );
          localStorage.setItem("access_token", data.accessToken); // Store token
        } catch (error) {
          console.log("Error loading user:", error);
        }
      },
    }),
  }),
});

export const { useRefreshAccessTokenQuery, useLoadUserQuery } = apiSlice;

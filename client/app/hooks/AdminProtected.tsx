import { redirect } from "next/navigation";
import { useSelector } from "react-redux";

import React from "react";

interface Props {
  children: React.ReactNode;
}
export default function AdminProtected({ children }: Props) {
  const { user } = useSelector((state: any) => state.auth);
  const isAdmin = user?.role === "admin";

  return isAdmin ? children : redirect("/");
}

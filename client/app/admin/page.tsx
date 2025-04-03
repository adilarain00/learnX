"use client";
import React from "react";
import AdminSidebar from "../components/Admin/sidebar/AdminSidebar";
import DashBoardHero from "../components/Admin/DashBoardHero";
import AdminProtected from "../hooks/AdminProtected";
import Heading from "../utils/Heading";

const page = () => {
  return (
    <div>
      <AdminProtected>
        <Heading
          title={`LearnX-Admin`}
          description="LearnX is a platform for students to learn and get help from teachers"
          keywords="Programming , MERN ,REDUX , Machine Learning"
        />
        <div className="flex h-full">
          {" "}
          <div className="1500px:w-[19%] w-1/5">
            <AdminSidebar />
          </div>
          <div></div>
          <div className="w-[85%] min-h-screen">
            <DashBoardHero isDashboard={true} />
          </div>
        </div>
      </AdminProtected>
    </div>
  );
};

export default page;

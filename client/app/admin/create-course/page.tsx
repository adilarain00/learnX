"use client";
import AdminSidebar from "@/app/components/Admin/sidebar/AdminSidebar";
import CreateCourse from "@/app/components/Admin/course/CreateCourse";
import DashBoardHero from "@/app/components/Admin/DashBoardHero";
import Heading from "@/app/utils/Heading";
import React from "react";

const page = () => {
  return (
    <div>
      <Heading
        title={`Create-Course-Admin`}
        description="LearnX is a platform for students to learn and get help from teachers"
        keywords="Programming , MERN ,REDUX , Machine Learning"
      />
      <div className="flex h-full">
        {" "}
        <div className="1500px:w-[19%] w-1/5">
          <AdminSidebar />
        </div>
        <div className="w-[85%]">
          <DashBoardHero />
          <CreateCourse />
        </div>
      </div>
    </div>
  );
};

export default page;

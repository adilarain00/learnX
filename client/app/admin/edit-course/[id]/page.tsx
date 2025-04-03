"use client";

import AdminSidebar from "@/app/components/Admin/sidebar/AdminSidebar";
import EditCourse from "@/app/components/Admin/course/EditCourse";
import DashBoardHero from "@/app/components/Admin/DashBoardHero";
import Heading from "@/app/utils/Heading";
import { useParams } from "next/navigation"; 
import React from "react";

const Page = () => {
  const params = useParams();
  const id = params?.id as string; 

  return (
    <div>
      <Heading
        title={`Edit Course - Admin`}
        description="Edit an existing course on the LearnX platform."
        keywords="Programming, MERN, REDUX, Machine Learning"
      />
      <div className="flex h-full">
        <div className="1500px:w-[19%] w-1/5">
          <AdminSidebar />
        </div>
        <div className="w-[85%]">
          <DashBoardHero />
          <EditCourse id={id} /> 
        </div>
      </div>
    </div>
  );
};

export default Page;

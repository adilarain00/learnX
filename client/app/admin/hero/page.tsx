"use client";

import React from "react";
import Heading from "@/app/utils/Heading";
import AdminProtected from "@/app/hooks/AdminProtected";
import EditHero from "@/app/components/Customization/EditHero";
import DashBoardHero from "../../components/Admin/DashBoardHero";
import AdminSidebar from "../../components/Admin/sidebar/AdminSidebar";

type Props = {};

const page = (props: Props) => {
  return (
    <div>
      <AdminProtected>
        <Heading
          title="LearnX - Admin"
          description="LearnX is a platform for students to learn and get help from teachers"
          keywords="Programming,MERN,Redux,Machine Learning"
        />
        <div className="flex h-screen">
          <div className="1500px:w-[15%] w-1/5">
            <AdminSidebar />
          </div>
          <div className="w-[85%]">
            <DashBoardHero />
            <EditHero />
          </div>
        </div>
      </AdminProtected>
    </div>
  );
};

export default page;

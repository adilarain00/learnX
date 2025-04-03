"use client";

import CourseDetailsPage from "@/app/components/Course/CourseDetailsPage";
import React, { FC, use } from "react";

interface Props {
  params: Promise<{ id: string }>; 
}

const Page: FC<Props> = ({ params }) => {
  const { id } = use(params); 
  return (
    <div>
      <CourseDetailsPage id={id} />
    </div>
  );
};

export default Page;

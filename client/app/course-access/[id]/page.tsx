"use client";

import { useLoadUserQuery } from "@/redux/features/api/apiSlice";
import { redirect, useParams } from "next/navigation";

import CourseContent from "@/app/components/Course/CourseContent";
import Loader from "@/app/components/Loader/Loader";
import React, { useEffect } from "react";

type Props = {
  params: any;
};

const Page = () => {
  const params = useParams();
    const id = params?.id as string;
  const { isLoading, error, data, refetch } = useLoadUserQuery(undefined, {});

  useEffect(() => {
    if (data) {
      const isPurchased = data.user.courses.find(
        (item: any) => item._id === id
      );
      console.log(data);
      console.log(isPurchased);
      if (!isPurchased) {
        redirect("/");
      }
    }
    if (error) {
      redirect("/");
    }
  }, [data, error, id]);

  return (
    <>
      {isLoading ? (
        <Loader />
      ) : (
        <div>
          <CourseContent id={id} user={data.user} />
        </div>
      )}
    </>
  );
};

export default Page;

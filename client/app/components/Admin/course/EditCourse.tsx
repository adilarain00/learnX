"use client";
import React, { FC, useEffect, useState } from "react";
import { useRouter } from "next/navigation"; // ✅ Fix: Use `next/navigation`
import { toast } from "react-hot-toast";

import {
  useEditCourseMutation,
  useGetAllCoursesQuery,
} from "../../../../redux/features/courses/courseApi";

import CourseInformation from "./CourseInformation";
import CourseOptions from "./CourseOptions";
import CourseContent from "./CourseContent";
import CoursePreview from "./CoursePreview";
import CourseData from "./CourseData";

type Props = {
  id: string;
};

const EditCourse: FC<Props> = ({ id }) => {
  console.log(id);
  const router = useRouter(); // ✅ Use correct router

  const [editCourse, { isSuccess, error }] = useEditCourseMutation();
  const { data, refetch } = useGetAllCoursesQuery(
    {},
    { refetchOnMountOrArgChange: true }
  );

  const editCourseData = data?.courses?.find((i: any) => i._id === id);
  console.log(editCourseData);

  const formattedBenefits = editCourseData?.benefits?.map((benefit: any) => ({
    title: benefit.title,
  })) ?? [];

  useEffect(() => {
    if (isSuccess) {
      toast.success("Course Updated successfully");
      router.push("/admin/courses"); // ✅ Correct Next.js router usage
    }
    if (error && "data" in error) {
      const errorMessage = (error as any).data.message;
      toast.error(errorMessage);
    }
  }, [isSuccess, error, router]);

  const [active, setActive] = useState(0);
  const [courseInfo, setCourseInfo] = useState({
    name: "",
    description: "",
    price: "",
    estimatedPrice: "",
    tags: "",
    level: "",
    categories: "",
    demoUrl: "",
    thumbnail: "",
  });

  const [benefits, setBenefits] = useState([{ title: "" }]);
  const [prerequisites, setPrerequisites] = useState([{ title: "" }]);
  const [courseContentData, setCourseContentData] = useState([
    {
      videoUrl: "",
      title: "",
      description: "",
      videoSection: "Untitled Section",
      links: [
        {
          title: "",
          url: "",
        },
      ],
      suggestion: "",
    },
  ]);

  const [courseData, setCourseData] = useState({});

  useEffect(() => {
    if (!editCourseData) return;

    setCourseInfo((prev) => ({
      ...prev,
      name: editCourseData.name || prev.name,
      description: editCourseData.description || prev.description,
      price: editCourseData.price || prev.price,
      estimatedPrice: editCourseData.estimatedPrice || prev.estimatedPrice,
      tags: editCourseData.tags || prev.tags,
      level: editCourseData.level || prev.level,
      categories: editCourseData.categories || prev.categories,
      demoUrl: editCourseData.demoUrl || prev.demoUrl,
      thumbnail: editCourseData?.thumbnail?.url || prev.thumbnail,
    }));

    setBenefits(formattedBenefits);
    setPrerequisites(editCourseData.prerequisites || []);
    setCourseContentData(editCourseData.courseData || []);
  }, [editCourseData, formattedBenefits]);

  const handleSubmit = async () => {
    const formattedCourseContentData = courseContentData.map(
      (courseContent) => ({
        videoUrl: courseContent.videoUrl,
        title: courseContent.title,
        description: courseContent.description,
        videoSection: courseContent.videoSection,
        links: courseContent.links.map((link) => ({
          title: link.title,
          url: link.url,
        })),
        suggestion: courseContent.suggestion,
      })
    );

    const data = {
      ...courseInfo,
      totalVideos: courseContentData.length,
      benefits,
      prerequisites,
      courseContent: formattedCourseContentData,
    };

    setCourseData(data);
  };

  const handleCourseCreate = async () => {
    await editCourse({ id: editCourseData?._id, data: courseData });
  };

  return (
    <div className="w-full flex min-h-screen">
      <div className="w-[80%]">
        {active === 0 && (
          <CourseInformation
            courseInfo={courseInfo}
            setCourseInfo={setCourseInfo}
            active={active}
            setActive={setActive}
          />
        )}

        {active === 1 && (
          <CourseData
            benefits={benefits}
            setBenefits={setBenefits}
            prerequisites={prerequisites}
            setPrerequisities={setPrerequisites}
            active={active}
            setActive={setActive}
          />
        )}

        {active === 2 && (
          <CourseContent
            active={active}
            setActive={setActive}
            courseContentData={courseContentData}
            setCourseContentData={setCourseContentData}
            handleSubmit={handleSubmit}
          />
        )}

        {active === 3 && (
          <CoursePreview
            active={active}
            setActive={setActive}
            courseData={courseData}
            handleCourseCreate={handleCourseCreate}
            isEdit={true}
          />
        )}
      </div>
      <div className="w-[20%] mt-[100px] h-screen fixed z-[-1] top-18 right-0">
        <CourseOptions active={active} setActive={setActive} />
      </div>
    </div>
  );
};

export default EditCourse;

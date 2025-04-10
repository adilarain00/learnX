"use client";
import { useGetUsersAllCoursesQuery } from "@/redux/features/courses/courseApi";
import { useGetHeroDataQuery } from "@/redux/features/layout/layoutApi";
import { useSearchParams } from "next/navigation";
import React, { useEffect, useState, Suspense } from "react";
import { styles } from "../styles/style";

import Loader from "../components/Loader/Loader";
import Header from "../components/Header";
import Heading from "../utils/Heading";
import CourseCard from "../components/Course/CourseCard";
import Footer from "../components/Footer";

const SearchParamsWrapper = ({ setSearch }: { setSearch: (value: string | null) => void }) => {
  const searchParams = useSearchParams();
  useEffect(() => {
    setSearch(searchParams?.get("title")?.toLowerCase() || null);
  }, [searchParams, setSearch]);

  return null;
};

const Page = () => {
  const { data, isLoading } = useGetUsersAllCoursesQuery(undefined, {});
  const { data: categoriesData } = useGetHeroDataQuery("Categories", {});

  const [route, setRoute] = useState("Login");
  const [open, setOpen] = useState(false);
  const [courses, setCourses] = useState<any[]>([]);
  const [category, setCategory] = useState("All");
  const [search, setSearch] = useState<string | null>(null);

  useEffect(() => {
    if (!data?.courses) return;

    let filteredCourses = data.courses;

    if (category !== "All") {
      filteredCourses = filteredCourses.filter(
        (item: any) => item.categories === category
      );
    }

    if (search) {
      filteredCourses = filteredCourses.filter((item: any) =>
        item.name.toLowerCase().includes(search)
      );
    }

    setCourses(filteredCourses);
  }, [data, category, search]);

  const categories = categoriesData?.layout?.categories || [];

  return (
    <div>
      {isLoading ? (
        <Loader />
      ) : (
        <>
          <Header
            route={route}
            setRoute={setRoute}
            open={open}
            setOpen={setOpen}
            activeItem={1}
          />
          <div className="w-[95%] 800px:w-[85%] m-auto min-h-[100vh]">
            <Heading
              title="All courses - LearnX"
              description="LearnX is a programming community."
              keywords="programming community, coding skills, expert insights, collaboration, growth"
            />
            <br />
            <Suspense fallback={<Loader />}>
              <SearchParamsWrapper setSearch={setSearch} />
            </Suspense>
            <div className="w-full flex items-center flex-wrap">
              <div
                className={`h-[35px] ${
                  category === "All" ? "bg-[crimson]" : "bg-[#5050cb]"
                } m-3 px-3 rounded-[30px] flex items-center justify-center font-Poppins cursor-pointer`}
                onClick={() => setCategory("All")}
              >
                All
              </div>
              {categories.map((item: any, index: number) => (
                <div
                  key={index}
                  className={`h-[35px] ${
                    category === item.title ? "bg-[crimson]" : "bg-[#5050cb]"
                  } m-3 px-3 rounded-[30px] flex items-center justify-center font-Poppins cursor-pointer`}
                  onClick={() => setCategory(item.title)}
                >
                  {item.title}
                </div>
              ))}
            </div>

            {courses.length === 0 && (
              <p
                className={`${styles.label} justify-center min-h-[50vh] flex items-center`}
              >
                {search
                  ? "No courses found!"
                  : "No courses found in this category. Please try another one!"}
              </p>
            )}

            <br />
            <br />

            <div className="grid grid-cols-1 gap-[20px] md:grid-cols-2 md:gap-[25px] lg:grid-cols-3 lg:gap-[25px] 1500px:grid-cols-4 1500px:gap-[35px] mb-12 border-0">
              {courses.map((item: any, index: number) => (
                <CourseCard item={item} key={index} />
              ))}
            </div>
          </div>
          <Footer />
        </>
      )}
    </div>
  );
};

export default Page;

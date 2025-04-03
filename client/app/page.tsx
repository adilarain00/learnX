"use client";
import React, { useState, FC } from "react";

import Reviews from "./components/Route/Reviews";
import Courses from "./components/Route/Courses";
import Hero from "./components/Route/Hero";
import Header from "./components/Header";
import Footer from "./components/Footer";
import FAQ from "./components/FAQ/FAQ";
import Heading from "./utils/Heading";

interface Props {}

const Page: FC<Props> = (props) => {
  const [open, setOpen] = useState(false);
  const [activeItem] = useState(0);
  const [route, setRoute] = useState("Login");

  return (
    <div>
      <Heading
        title="LEARNX | Welcome to LearnX"
        description="LearnX is a platform for students to learn and get help from teachers"
        keywords="Programming , MERN ,REDUX , Machine Learning"
      />
      <Header
        open={open}
        setOpen={setOpen}
        activeItem={activeItem}
        setRoute={setRoute}
        route={route}
      />
      <Hero />
      <Courses />
      <Reviews />
      <FAQ />
      <Footer />
    </div>
  );
};
export default Page;

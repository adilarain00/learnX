"use client";

import React, { useState, FC } from "react";
import { useSelector } from "react-redux";

import Profile from "../components/Profile/Profile";
import Protected from "../hooks/useProtected";
import Header from "../components/Header";
import Footer from "../components/Footer";
import Heading from "../utils/Heading";

interface Props {}

const Page: FC<Props> = (props) => {
  const [open, setOpen] = useState(false);
  const [activeItem] = useState(5);
  const [route, setRoute] = useState("Login");
  const { user } = useSelector((state: any) => state.auth);

  return (
    <div>
      <Protected>
        <Heading
          title={`${user?.name} profile-Elearning`}
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
        <Profile user={user} />
        <Footer />
      </Protected>
    </div>
  );
};
export default Page;

"use client";
import React, { FC, useEffect, useState } from "react";

import { HiOutlineMenuAlt3, HiOutlineUserCircle } from "react-icons/hi";
import { useLoadUserQuery } from "@/redux/features/api/apiSlice";
import { useSession } from "next-auth/react";

import Link from "next/link";
import NavItems from "../utils/NavItems";
import ThemeSwitcher from "../utils/ThemeSwitcher";
import CustomModal from "../utils/CustomModal";
import Login from "./Auth/Login";
import SignUp from "./Auth/SignUp";
import Verification from "./Auth/Verification";
import Image from "next/image";
import avatar from "../../public/assests/avatardefault.jpeg";

import {
  useLogOutQuery,
  useSocialAuthMutation,
} from "../../redux/features/auth/authApi";

import toast from "react-hot-toast";
import Loader from "./Loader/Loader";

interface HeaderProps {
  open: boolean;
  setOpen: (open: boolean) => void;
  activeItem: number;
  route: string;
  setRoute: (route: string) => void;
}
const Header: FC<HeaderProps> = ({
  activeItem,
  setOpen,
  open,
  route,
  setRoute,
}) => {
  const [active, setActive] = useState(false);
  const [openSidebar, setOpenSidebar] = useState(false);

  const { data } = useSession();
  const {
    data: userData,
    isLoading,
    refetch,
  } = useLoadUserQuery(undefined, {});

  const [socialAuth, { isSuccess, error }] = useSocialAuthMutation();
  const [logout, setLogOut] = useState(false);
  const {} = useLogOutQuery(undefined, { skip: !logout ? true : false });

  useEffect(() => {
    if (data && !userData) {
      socialAuth({
        email: data?.user?.email,
        name: data?.user?.name,
        avatar: data?.user?.image,
      })
        .unwrap()
        .then(() => {
          toast.success("Login Successfully");
          refetch();
        })
        .catch((err: any) => {
          if (err?.data?.message) {
            toast.error(err.data.message);
          }
        });
    }

    if (data === null && !userData) {
      setLogOut(true);
    }
  }, [data, userData, socialAuth, refetch]);

  if (typeof window !== "undefined") {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 85) {
        setActive(true);
      } else {
        setActive(false);
      }
    });
  }

  const handleClose = (e: any) => {
    if (e.target.id === "screen") {
      {
        setOpenSidebar(false);
      }
    }
  };
  return (
    <>
      {isLoading ? (
        <Loader />
      ) : (
        <div className="w-full relative transition-property: all;">
          <div
            className={`${
              active
                ? "dark:bg-opacity-50 bg-white dark:bg-gradient-to-b dark:from-gray-900 dark:to-black fixed top-0 left-0 w-full h-[80px] z-[80] border-b dark:border-[#ffffff1c] shadow-xl transition duration-500"
                : "w-full border-b dark:border-[#ffffff1c] h-[80px] z-[80] dark:shadow"
            }`}
          >
            <div className="w-[95%] 800px:w-[92%] m-auto py-2 h-full transition-property: all;">
              <div className="w-full h-[80px] flex items-center justify-between p-3">
                <div className="relative inline-block">
                  <span className="absolute top-1/3 cursor-pointer left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-[#ff0f0f] text-[70px] font-bold opacity-20">
                    X
                  </span>
                  <Link
                    href={"/"}
                    className="relative z-10 text-[25px] font-Poppins font-[600] text-black dark:text-white"
                  >
                    LEARN
                  </Link>
                </div>

                <div className="flex items-center">
                  <NavItems activeItem={activeItem} isMobile={false} />
                  <ThemeSwitcher />
                  {/* only for mobile */}
                  <div className="800px:hidden">
                    <HiOutlineMenuAlt3
                      size={25}
                      className="cursor-pointer dark:text-white text-black"
                      onClick={() => setOpenSidebar(true)}
                    />
                  </div>
                  {userData ? (
                    <Link href={"/profile"}>
                      <Image
                        src={
                          userData?.user.avatar
                            ? userData.user.avatar.url
                            : avatar
                        }
                        alt=""
                        width={30}
                        height={30}
                        className="w-[30px] h-[30px] rounded-full cursor-pointer"
                        style={{
                          border:
                            activeItem === 5 ? "2px solid #37a39a" : "none",
                        }}
                      />
                    </Link>
                  ) : (
                    <HiOutlineUserCircle
                      size={25}
                      className="hidden 800px:block cursor-pointer dark:text-white text-black"
                      onClick={() => setOpen(true)}
                    />
                  )}
                </div>
              </div>
            </div>

            {/* mobile sidebar */}
            {openSidebar && (
              <div
                className="fixed w-full h-screen top-0 left-0 z-[99999]  dark:bg-[unset] bg-[#00000024]"
                onClick={handleClose}
                id="screen"
              >
                <div className="w-[70%] fixed  z-[999999999]  h-screen bg-white dark:bg-slate-900 dark:bg-opacity-90 top-0 right-0">
                  <NavItems activeItem={activeItem} isMobile={true} />
                  {userData?.user ? (
                    <Link href={"/profile"} className="flex justify-center">
                      <Image
                        src={
                          userData?.user.avatar
                            ? userData.user.avatar.url
                            : avatar
                        }
                        alt=""
                        width={30}
                        height={30}
                        className="w-[30px] h-[30px] rounded-full cursor-pointer"
                        style={{
                          border:
                            activeItem === 5 ? "2px solid #37a39a" : "none",
                        }}
                      />
                    </Link>
                  ) : (
                    <HiOutlineUserCircle
                      size={25}
                      className="hidden 800px:block cursor-pointer dark:text-white text-black"
                      onClick={() => setOpen(true)}
                    />
                  )}
                  <br />
                  <br />
                  <p className="text-[16px] flex justify-center px-2 pl-5 text-black dark:text-white">
                    Copyright © 2023 ELearning
                  </p>
                </div>
              </div>
            )}
          </div>
          {route === "Login" && (
            <>
              {open && (
                <CustomModal
                  open={open}
                  setOpen={setOpen}
                  setRoute={setRoute}
                  activeItem={activeItem}
                  component={Login}
                  refetch={refetch}
                />
              )}
            </>
          )}

          {route === "Sign-Up" && (
            <>
              {open && (
                <CustomModal
                  open={open}
                  setOpen={setOpen}
                  setRoute={setRoute}
                  activeItem={activeItem}
                  component={SignUp}
                />
              )}
            </>
          )}

          {route === "Verification" && (
            <>
              {open && (
                <CustomModal
                  open={open}
                  setOpen={setOpen}
                  setRoute={setRoute}
                  activeItem={activeItem}
                  component={Verification}
                />
              )}
            </>
          )}
        </div>
      )}
    </>
  );
};

export default Header;

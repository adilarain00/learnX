import Link from "next/link";
import React, { FC } from "react";

interface Props {
  activeItem: number;
  isMobile: boolean;
}
export const navItemsData = [
  {
    name: "Home",
    url: "/",
  },
  {
    name: "Courses",
    url: "/courses",
  },
  {
    name: "About",
    url: "/about",
  },
  {
    name: "Policy",
    url: "/policy",
  },
  {
    name: "FAQ",
    url: "/faq",
  },
];
const NavItems: FC<Props> = ({ activeItem, isMobile }) => {
  return (
    <>
      <div className="hidden 800px:flex">
        {navItemsData &&
          navItemsData.map((i, index) => (
            <Link href={`${i.url}`} key={index} passHref>
              <span
                className={`${
                  activeItem === index
                    ? "dark:text-[#9e2828] font-semibold text-[crimson]"
                    : "dark:text-white text-black"
                } text-[18px] px-6 font-Poppins font-[400]`}
              >
                {i.name}
              </span>
            </Link>
          ))}
      </div>
      {isMobile && (
        <div className="800px:hidden mt-5">
          <div className="w-full text-center py-6">
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
          </div>
          {navItemsData &&
            navItemsData.map((i, index) => (
              <Link href="/" passHref key={index}>
                <span
                  className={`${
                    activeItem === index
                      ? "dark:text-[#9e2828] font-semibold text-[crimson]"
                      : "dark:text-white text-black"
                  } py-5 text-[18px] px-6 font-Poppins font-[400] flex justify-center`}
                >
                  {i.name}
                </span>
              </Link>
            ))}
        </div>
      )}
    </>
  );
};

export default NavItems;

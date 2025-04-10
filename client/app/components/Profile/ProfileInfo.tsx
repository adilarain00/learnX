import { useLoadUserQuery } from "../../../redux/features/api/apiSlice";
import React, { FC, useEffect, useState } from "react";
import { styles } from "../../../app/styles/style";
import { AiOutlineCamera } from "react-icons/ai";
import { toast } from "react-hot-toast";

import Image from "next/image";
import Loader from "../Loader/Loader";
import avatardefault from "../../../public/assests/avatardefault.jpeg";

import {
  useEditprofileMutation,
  useUpdateAvatarMutation,
} from "../../../redux/features/user/userApi";

type Props = {
  avatar: string | null;
  user: any;
};

const ProfileInfo: FC<Props> = ({ avatar, user }) => {
  const [name, setName] = useState(user && user.name);
  const [updateAvatar, { isSuccess, isLoading, error }] =
    useUpdateAvatarMutation();
  const [
    editprofile,
    { isSuccess: success, error: updateError, isLoading: updateLoading },
  ] = useEditprofileMutation();

  const [loadUser, setLoadUser] = useState(false);
  const {} = useLoadUserQuery(undefined, { skip: loadUser ? false : true });

  const imageHandler = async (e: any) => {
    const fileReader = new FileReader();

    fileReader.onload = () => {
      if (fileReader.readyState === 2) {
        const avatar = fileReader.result;

        updateAvatar(avatar);
      }
    };
    fileReader.readAsDataURL(e.target.files[0]);
  };

  useEffect(() => {
    if (isSuccess) {
      setLoadUser(true);
    }
    if (error || updateError) {
      console.log(error);
    }
    if (success) {
      toast.success("Profile updated successfully!");
      setLoadUser(true);
    }
  }, [isSuccess, error, success, updateError]);

  const handleSubmit = async (e: any) => {
    e.preventDefault();
    if (name !== "") {
      editprofile({
        name,
      });
    }
  };

  return (
    <>
      <div className="w-full flex justify-center">
        {isLoading ? (
          <Loader />
        ) : (
          <div className="relative">
            <Image
              src={
                user.avatar || avatar
                  ? user.avatar.url || avatar
                  : avatardefault
              }
              alt=""
              width={120}
              height={120}
              className="w-[120px] h-[120px] cursor-pointer border-[3px] border-[#37a39a] rounded-full"
            />
            <input
              type="file"
              name=""
              id="avatar"
              className="hidden"
              onChange={imageHandler}
              accept="image/png,image/jpg,image/jpeg,image/webp"
            />
            <label htmlFor="avatar">
              <div className="w-[30px] h-[30px] bg-slate-900 rounded-full absolute bottom-2 right-2 flex items-center justify-center cursor-pointer">
                <AiOutlineCamera size={20} className="z-1" />
              </div>
            </label>
          </div>
        )}
      </div>
      <br />
      <br />
      {updateLoading ? (
        <Loader />
      ) : (
        <div className="w-full pl-6 800px:pl-10">
          <form onSubmit={handleSubmit}>
            <div className="800px:w-[50%] m-auto block pb-4">
              <div className="w-[100%]">
                <label className="block pb-2">Full Name</label>
                <input
                  type="text"
                  className={`${styles.input} !w-[95%] mb-4 800px:mb-0`}
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="w-[100%] pt-2">
                <label className="block pb-2">Email Address</label>
                <input
                  type="text"
                  readOnly
                  className={`${styles.input} !w-[95%] mb-1 800px:mb-0`}
                  required
                  value={user?.email}
                />
              </div>
              <input
                type="submit"
                className="w-full 800px:w-[250px] h-[40px] border border-[cyan] text-center dark:text-white  rounded-[3px] mt-8 cursor-pointer bg-gradient-to-r from-cyan-500 to-blue-500 text-white transition-all duration-300 ease-in-out hover:from-blue-500 hover:to-cyan-500 hover:scale-105"
                required
                value="Update"
              />
            </div>
          </form>
          <br />
        </div>
      )}
    </>
  );
};

export default ProfileInfo;

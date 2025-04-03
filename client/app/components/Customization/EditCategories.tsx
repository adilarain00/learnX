import {
  useEditLayoutMutation,
  useGetHeroDataQuery,
} from "@/redux/features/layout/layoutApi";

import { styles } from "@/app/styles/style";
import { AiOutlineDelete } from "react-icons/ai";
import { IoMdAddCircleOutline } from "react-icons/io";
import { toast } from "react-hot-toast";

import React, { useEffect, useState } from "react";
import Loader from "../Loader/Loader";

type Props = {};

const EditCategories = (props: Props) => {
  const { data, isLoading, refetch } = useGetHeroDataQuery("Categories", {
    refetchOnMountOrArgChange: true,
  });

  const [editLayout, { isSuccess: layoutSuccess, error }] =
    useEditLayoutMutation();

  const [categories, setCategories] = useState<any[]>([]);

  // Load categories when data is available
  useEffect(() => {
    if (data?.layout?.categories) {
      setCategories(data.layout.categories);
    }

    if (layoutSuccess) {
      refetch();
      toast.success("Categories updated successfully");
    }

    if (error && "data" in error) {
      const errorData = error as any;
      toast.error(errorData?.data?.message);
    }
  }, [data, layoutSuccess, error, refetch]);

  // Handle category title change
  const handleCategoryChange = (id: string, value: string) => {
    setCategories((prevCategories) =>
      prevCategories.map((category) =>
        category._id === id ? { ...category, title: value } : category
      )
    );
  };

  // Add new category
  const newCategoryHandler = () => {
    if (
      categories.length > 0 &&
      categories[categories.length - 1].title.trim() === ""
    ) {
      toast.error("Category title cannot be empty");
      return;
    }

    // Generate a temporary unique ID
    const tempId = `temp-${Date.now()}`;

    setCategories((prevCategories) => [
      ...prevCategories,
      { _id: tempId, title: "" },
    ]);
  };

  // Check if categories are unchanged
  const areCategoriesUnchanged = (
    originalCategories: any[],
    newCategories: any[]
  ) => {
    return JSON.stringify(originalCategories) === JSON.stringify(newCategories);
  };

  // Check if any category title is empty
  const isAnyCategoryTitleEmpty = (categories: any[]) => {
    return categories.some((category) => category.title.trim() === "");
  };

  // Edit & save categories
  const editCategoriesHandler = async () => {
    if (
      !areCategoriesUnchanged(data?.layout?.categories ?? [], categories) &&
      !isAnyCategoryTitleEmpty(categories)
    ) {
      await editLayout({
        type: "Categories",
        categories,
      });
    }
  };

  return (
    <>
      {isLoading ? (
        <Loader />
      ) : (
        <div className="mt-[120px] text-center">
          <h1 className={`${styles.title}`}>All Categories</h1>

          {/* Category Inputs */}
          {categories.map((item, index) => (
            <div className="p-3" key={item._id || index}>
              <div className="flex items-center w-full justify-center">
                <input
                  className={`${styles.input} !w-[unset] !border-none !text-[20px]`}
                  value={item.title}
                  onChange={(e) =>
                    handleCategoryChange(item._id, e.target.value)
                  }
                  placeholder="Enter category title..."
                />
                <AiOutlineDelete
                  className="dark:text-white text-black text-[18px] cursor-pointer"
                  onClick={() =>
                    setCategories((prevCategories) =>
                      prevCategories.filter((i) => i._id !== item._id)
                    )
                  }
                />
              </div>
            </div>
          ))}

          {/* Add New Category Button */}
          <br />
          <br />
          <div className="w-full flex justify-center">
            <IoMdAddCircleOutline
              className="dark:text-white text-black text-[25px] cursor-pointer"
              onClick={newCategoryHandler}
            />
          </div>

          {/* Save Button */}
          <div
            className={`${
              styles.button
            } !w-[100px] !min-h-[40px] !h-[40px] dark:text-white text-black bg-[#cccccc34] 
              ${
                areCategoriesUnchanged(data?.layout?.categories ?? [], categories) ||
                isAnyCategoryTitleEmpty(categories)
                  ? "!cursor-not-allowed"
                  : "!cursor-pointer !bg-[#42d383]"
              }
              !rounded absolute bottom-12 right-12`}
            onClick={
              areCategoriesUnchanged(data?.layout?.categories ?? [], categories) ||
              isAnyCategoryTitleEmpty(categories)
                ? () => null
                : editCategoriesHandler
            }
          >
            Save
          </div>
        </div>
      )}
    </>
  );
};

export default EditCategories;
